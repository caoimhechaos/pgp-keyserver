/**
 * Copyright (c) 2014, Caoimhe Chaos <caoimhechaos@protonmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * * Neither the name of Ancient Solutions nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"database/cassandra"
	"encoding/hex"
	"errors"
	"expvar"
	"log"
	"net/http"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp"
)

var pksreqs *expvar.Int = expvar.NewInt("num-pks-reqs")
var pksunknownreqs *expvar.Int = expvar.NewInt("num-pks-unknown-reqs")
var pksaddreqs *expvar.Int = expvar.NewInt("num-pks-add-reqs")
var pkslookupreqs *expvar.Int = expvar.NewInt("num-pks-lookup-reqs")
var pkslookupkeysfound *expvar.Int = expvar.NewInt("num-pks-lookup-keys-found")
var pksaddrequesterrors *expvar.Map = expvar.NewMap("num-pkcs-add-request-errors")
var pksadderrors *expvar.Map = expvar.NewMap("num-pkcs-add-errors")

// The handler for requests to /pks. Will distribute them automatically by
// request type; can be used as an HTTP handler directly
type PksHandler struct {
	client   *cassandra.RetryCassandraClient
	keyspace string
	http.Handler
}

// Set up a new PKS handler using the Cassandra database at "dbserver" and
// querying the given "keyspace". Will return the newly setup PKS handler
// or an error indicating why it failed.
func NewPksHandler(dbserver, keyspace string) (*PksHandler, error) {
	var err error
	var client *cassandra.RetryCassandraClient

	client, err = cassandra.NewRetryCassandraClientTimeout(dbserver,
		10*time.Second)
	if err != nil {
		return nil, err
	}

	ire, err := client.SetKeyspace(keyspace)
	if ire != nil {
		return nil, errors.New("Error setting keyspace to " + keyspace +
			": " + ire.Why)
	}
	if err != nil {
		return nil, errors.New("Error setting keyspace to " + keyspace +
			": " + err.Error())
	}
	return &PksHandler{
		client:   client,
		keyspace: keyspace,
	}, nil
}

// Add the given "keydata" as a new key to the database. If this fails, a
// descriptive error message is returned as error and the int is set to
// the appropriate HTTP response code.
func (self *PksHandler) Add(keydata string) (int, error) {
	var ts int64 = time.Now().Unix()
	var entities openpgp.EntityList
	var entity *openpgp.Entity
	var err error

	// Read all keys from the input; there can be multiple and we still
	// wouldn't care.
	entities, err = openpgp.ReadArmoredKeyRing(strings.NewReader(keydata))
	if err != nil {
		log.Print("Unable to decode armored key ring: ", err)
		pksaddrequesterrors.Add("invalid-armored-key", 1)
		return http.StatusBadRequest, err
	}

	for _, entity = range entities {
		var mmap map[string]map[string][]*cassandra.Mutation
		var mutations []*cassandra.Mutation
		var mutation *cassandra.Mutation
		var col *cassandra.Column

		var ire *cassandra.InvalidRequestException
		var ue *cassandra.UnavailableException
		var te *cassandra.TimedOutException

		// Reverse the fingerprint so it can be used as a key.
		// TODO(caoimhe): look for existing keys and merge existing
		// signatures.
		var rev_fp []byte = make([]byte, len(entity.PrimaryKey.Fingerprint))
		for i, x := range entity.PrimaryKey.Fingerprint {
			rev_fp[len(entity.PrimaryKey.Fingerprint)-i-1] = x
		}

		col = cassandra.NewColumn()
		col.Name = []byte("keydata")
		col.Value = []byte(keydata)
		col.Timestamp = ts
		mutation = cassandra.NewMutation()
		mutation.ColumnOrSupercolumn = cassandra.NewColumnOrSuperColumn()
		mutation.ColumnOrSupercolumn.Column = col
		mutations = append(mutations, mutation)

		mmap = make(map[string]map[string][]*cassandra.Mutation)
		mmap[string(rev_fp)] = make(map[string][]*cassandra.Mutation)
		mmap[string(rev_fp)]["keys"] = mutations

		ire, ue, te, err = self.client.BatchMutate(mmap,
			cassandra.ConsistencyLevel_ONE)
		if ire != nil {
			log.Println("Invalid request: ", ire.Why)
			pksadderrors.Add("invalid-request", 1)
			err = errors.New(ire.String())
			return http.StatusInternalServerError, err
		}
		if ue != nil {
			log.Println("Unavailable")
			pksadderrors.Add("unavailable", 1)
			err = errors.New(ue.String())
			return http.StatusInternalServerError, err
		}
		if te != nil {
			log.Println("Request to database backend timed out")
			pksadderrors.Add("timeout", 1)
			err = errors.New(te.String())
			return http.StatusInternalServerError, err
		}
		if err != nil {
			log.Println("Generic error: ", err)
			pksadderrors.Add("os-error", 1)
			err = errors.New(err.Error())
			return http.StatusInternalServerError, err
		}
	}
	return http.StatusCreated, nil
}

// Retrieve the key with the given key ID "keyid" from the database.
// Returns an error in case of failure and prints the PEM encoded key
// data to the client otherwise.
func (self *PksHandler) Get(w http.ResponseWriter, keyid string) error {
	var cp *cassandra.ColumnParent = cassandra.NewColumnParent()
	var sp *cassandra.SlicePredicate = cassandra.NewSlicePredicate()
	var kr *cassandra.KeyRange = cassandra.NewKeyRange()
	var slices []*cassandra.KeySlice
	var ire *cassandra.InvalidRequestException
	var ue *cassandra.UnavailableException
	var te *cassandra.TimedOutException
	var ks *cassandra.KeySlice
	var kid []byte
	var key, endkey []byte
	var err error
	var i int

	kid, err = hex.DecodeString(strings.TrimPrefix(keyid, "0x"))
	if err != nil {
		return err
	}

	// Reverse the key ID. Also, copy it into an end key.
	for i = len(kid) - 1; i >= 0; i-- {
		key = append(key, kid[i])
		endkey = append(endkey, kid[i])
	}
	// The end key must be the start key + 1.
	// If the start key is all 0xFF, the end key should be all 0x00.
	for i = len(endkey) - 1; i >= 0; i++ {
		if endkey[i] == 255 {
			endkey[i] = 0
		} else {
			endkey[i] += 1
			break
		}
	}

	cp.ColumnFamily = "keys"
	sp.ColumnNames = [][]byte{[]byte("keydata")}
	kr.StartKey = key
	kr.EndKey = endkey

	slices, ire, ue, te, err = self.client.GetRangeSlices(
		cp, sp, kr, cassandra.ConsistencyLevel_ONE)
	if ire != nil {
		return errors.New(ire.Why)
	} else if ue != nil {
		return errors.New("Unavailable")
	} else if te != nil {
		return errors.New("Timed out")
	} else if err != nil {
		return err
	}
	pkslookupkeysfound.Add(int64(len(slices)))
	// Print all keydata columns to stdout, it's what the user wants.
	for _, ks = range slices {
		var cos *cassandra.ColumnOrSuperColumn
		for _, cos = range ks.Columns {
			var col = cos.Column
			if string(col.Name) != "keydata" {
				log.Print("Got column " + string(col.Name) +
					" which I didn't ask for?")
				continue
			}

			w.Write(col.Value)
		}
	}
	return nil
}

// HTTP response generator of the PKS handler.
func (self *PksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var status int
	var ops []string = strings.Split(r.RequestURI, "/")
	var op string

	// Try to extract the requested operation from the URL.
	// The URL would be something like /pks/add or /pks/lookup
	for i, c := range ops {
		if len(c) > 0 && c != "pks" {
			if strings.Contains(c, "?") {
				var pcs = strings.SplitN(c, "?", 2)
				c = pcs[0]
			}
			op = c
			ops = ops[i+1 : len(ops)]
			break
		}
	}

	pksreqs.Add(1)

	if err = r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print("Error parsing form values: ", err)
		return
	}

	// Call different handlers based on the requested operations.
	// Format the result for the clients leisure.
	switch op {
	default:
		{
			pksunknownreqs.Add(1)
			log.Print("Requested operation ", op, " not supported")
			http.Error(w, "Requested operation "+op+" not supported",
				http.StatusBadRequest)
			return
		}
	case "add":
		{
			pksaddreqs.Add(1)

			if r.PostFormValue("keytext") == "" {
				pksaddrequesterrors.Add("missing-keytext", 1)
				http.Error(w, "No key in request object", http.StatusBadRequest)
				return
			}
			status, err = self.Add(r.PostFormValue("keytext"))
			if err == nil {
				http.Error(w, "Created", http.StatusCreated)
			} else {
				http.Error(w, err.Error(), status)
			}
		}
	case "lookup":
		{
			pkslookupreqs.Add(1)
			err = self.Get(w, r.FormValue("search"))
			if err != nil {
				log.Print("Error retrieving key " + r.FormValue("searc") +
					": " + err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}
}
