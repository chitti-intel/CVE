package mongo

import (
	"context"
	"log"

	"echo/pkg"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type EntryService struct {
	collection *mongo.Collection
}

func NewEntryService(client *Client, dbName string, collectionName string) (*EntryService, error) {
	collection := client.GetCollection(dbName, collectionName)
	_, err := collection.Indexes().CreateOne(context.TODO(), entryModelDigestIndex())
	_, err = collection.Indexes().CreateOne(context.TODO(), entryModelUuidIndex())
	if err != nil {
		return nil, err
	}
	return &EntryService{collection}, nil
}

func (p *EntryService) Create(u *root.Entry) (*mongo.InsertOneResult, error) {
	entry := newEntryModel(u)

	insertResult, err := p.collection.InsertOne(context.TODO(), &entry)
	return insertResult, err
}

func (p *EntryService) Exists(digest string) (bool, error) {
	filter := bson.D{{"digest", digest}}

	count, err := p.collection.CountDocuments(context.TODO(), filter)

	if err != nil {
		return false, err
	}
	if count == 1 {
		return true, nil
	}

	return false, nil
}

func (p *EntryService) GetByUuid(uuid string) (*root.Entry, error) {
	model := entryModel{}
	err := p.collection.FindOne(context.TODO(), bson.M{"uuid": uuid}).Decode(&model)
	return model.toRootEntry(), err
}

func (p *EntryService) GetByDigest(digest string) (*root.Entry, error) {
	model := entryModel{}
	err := p.collection.FindOne(context.TODO(), bson.M{"digest": digest}).Decode(&model)
	return model.toRootEntry(), err
}

func (p *EntryService) GetAllbyName(name string) ([]*root.Entry, error) {
	var results []*root.Entry
	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := p.collection.Find(context.TODO(), bson.D{{"name", name}}, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var elem root.Entry
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		results = append(results, &elem)
	}

	if err := cur.Err(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	return results, err
}

func (p *EntryService) GetAll() ([]*root.Entry, error) {
	var results []*root.Entry
	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := p.collection.Find(context.TODO(), bson.D{{}}, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var elem root.Entry
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		results = append(results, &elem)
	}

	if err := cur.Err(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	return results, err
}
