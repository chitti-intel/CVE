package mongo_test

import (
	"context"
	"echo/pkg"
	"echo/pkg/mongo"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"testing"
)

const (
	mongoUrl            = "mongodb://localhost:27017"
	dbName              = "test_cve_db_v2"
	entryCollectionName = "cve_entry"
)

func Test_EntryService(t *testing.T) {
	t.Run("CreateEntry", createEntry_should_insert_entry_into_mongo)

	t.Run("Exists", Exists_should_return_if_doc_exists)

	t.Run("GetByUuid", GetByUuid_should_retrive_cve_report)
}

func createEntry_should_insert_entry_into_mongo(t *testing.T) {
	//Arrange
	c, err := mongo.GetClient(mongoUrl)
	if err != nil {
		log.Fatalf("Unable to connect to mongo: %s\n", err)
	}
	defer func() {
		// err = c.Disconnect()
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Println("Connection to MongoDB closed.")
		// err = c.DropDatabase(dbName)
		// if err != nil {
		// 	log.Fatal(err)
		// }
	}()
	entryService, err := mongo.NewEntryService(c, dbName, entryCollectionName)

	if err != nil {
		log.Fatal(err)
	}

	testUuid := "abcdef12345"
	testName := "busybox:latest"
	testDigest := "sha256:asdasd0sdksdlask"
	testTimestamp := "13th Feb 2023"
	testSbomPath := "/test/path"
	testCVE := "Scan report"
	entry := root.Entry{
		Uuid:      testUuid,
		Name:      testName,
		Digest:    testDigest,
		Timestamp: testTimestamp,
		SbomPath:  testSbomPath,
		CVE:       testCVE,
	}

	//Act
	_, err = entryService.Create(&entry)

	//Assert
	if err != nil {
		// t.Error("Unable to create user: %s", err)
		t.Error(err)
	}
	var results []*root.Entry
	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := c.GetCollection(dbName, entryCollectionName).Find(context.TODO(), bson.D{{}}, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var elem root.Entry
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
		}

		results = append(results, &elem)
	}

	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	count := len(results)
	if count != 1 {
		t.Error("Incorrect number of results. Expected `1`, got: `%i`", count)
	}
	if results[0].Name != entry.Name {
		// t.Error("Incorrect Username. Expected `%s`, Got: `%s`", testUsername, results[0].Username)
		t.Error("Incorrect Image Name")
	}
}

func GetByUuid_should_retrive_cve_report(t *testing.T) {
	c, err := mongo.GetClient(mongoUrl)
	if err != nil {
		log.Fatalf("Unable to connect to mongo: %s\n", err)
	}
	defer func() {
		err = c.DropDatabase(dbName)
		if err != nil {
			log.Fatal(err)
		}
		err = c.Disconnect()
		if err != nil {
			log.Fatal(err)
		}
	}()
	entryService, err := mongo.NewEntryService(c, dbName, entryCollectionName)

	if err != nil {
		log.Fatal(err)
	}

	testUuid := "abcdef12345"

	root_entry, err := entryService.GetByUuid(testUuid)

	fmt.Println(root_entry.CVE)
	if root_entry.CVE != "Scan report" {
		t.Error("Incorrect CVE Report")
	}
}

func Exists_should_return_if_doc_exists(t *testing.T) {
	c, err := mongo.GetClient(mongoUrl)
	if err != nil {
		log.Fatalf("Unable to connect to mongo: %s\n", err)
	}
	defer func() {

	}()
	entryService, err := mongo.NewEntryService(c, dbName, entryCollectionName)

	testDigest := "sha256:asdasd0sdksdlask"

	exists, err := entryService.Exists(testDigest)
	if err != nil {
		log.Fatalf("Unable to check if entry exists %s\n", err)
	}
	if exists != true {
		t.Error("Expected true")
	}
}
