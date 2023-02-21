package mongo

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// type Session struct {
// 	session *mgo.Session
// }

// func NewSession(url string) (*Session, error) {
// 	session, err := mgo.Dial("localhost:27017")
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Session{session}, err

// }

// func (s *Session) Copy() *Session {
// 	return &Session{s.session.Copy()}
// }

// func (s *Session) GetCollection(db string, col string) *mgo.Collection {
// 	return s.session.DB(db).C(col)
// }

// func (s *Session) Close() {
// 	if s.session != nil {
// 		s.session.Close()
// 	}
// }

// func (s *Session) DropDatabase(db string) error {
// 	if s.session != nil {
// 		return s.session.DB(db).DropDatabase()
// 	}
// 	return nil
// }

type Client struct {
	client *mongo.Client
}

func GetClient(url string) (*Client, error) {
	ctx := context.TODO()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(url))
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

func (c *Client) GetCollection(db string, col string) *mongo.Collection {
	return c.client.Database(db).Collection(col)
}

func (c *Client) Disconnect() error {
	return c.client.Disconnect(context.TODO())
}

func (c *Client) DropDatabase(db string) error {
	return c.client.Database(db).Drop(context.TODO())
}
