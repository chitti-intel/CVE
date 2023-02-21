package mongo

import (
	"echo/pkg"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type entryModel struct {
	Id primitive.ObjectID `bson:"_id,omitempty"`
	// Username string
	// Password string
	Uuid      string
	Name      string
	Digest    string
	Timestamp string
	SbomPath  string
	CVE       *root.Report
}

func entryModelDigestIndex() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.M{
			"digest": 1,
		},
		Options: options.Index().SetUnique(true),
	}
}

func entryModelUuidIndex() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.M{
			"uuid": 1,
		},
		Options: options.Index().SetUnique(true),
	}
}

func newEntryModel(e *root.Entry) *entryModel {
	return &entryModel{
		Uuid:      e.Uuid,
		Name:      e.Name,
		Digest:    e.Digest,
		Timestamp: e.Timestamp,
		SbomPath:  e.SbomPath,
		CVE:       e.CVE}
}

func (e *entryModel) toRootEntry() *root.Entry {
	return &root.Entry{
		Id:        e.Id.Hex(),
		Uuid:      e.Uuid,
		Name:      e.Name,
		Digest:    e.Digest,
		Timestamp: e.Timestamp,
		SbomPath:  e.SbomPath,
		CVE:       e.CVE}
}
