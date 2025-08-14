package mongodb

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/subosito/gotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func InitMongoUri() string {
	err := gotenv.Load("./.env")
	if err != nil {
		log.Println("Error loading .env file:", err)
	}
	uri := "mongodb://localhost:27017"
	uriEnv := os.Getenv("MONGODB_URI")
	if uriEnv != "" {
		uri = uriEnv
	}
	return uri
}

func InitUserCollection() *mongo.Collection {
	clientOptions := options.Client().ApplyURI(InitMongoUri())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("Could not connect to MongoDB:", err)
	}

	fmt.Println("MongoDB connected to 'users' collection successfully.")
	return client.Database("testdb").Collection("users")
}
