package main

import (
	"laughing-octo-goggles/main.go/mongodb"
	servegin "laughing-octo-goggles/main.go/serve-gin"

	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection

func main() {
	userCollection = mongodb.InitUserCollection()
	servegin.Init(userCollection)
}
