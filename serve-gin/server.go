package servegin

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/subosito/gotenv"
	"go.mongodb.org/mongo-driver/mongo"
)

func Init(userCollection *mongo.Collection) {

	err := gotenv.Load("./.env")
	if err != nil {
		log.Println("Error loading .env file:", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	AddUserRoutes(userCollection, r)

	log.Printf("Serving Gin at http://localhost:%s/\n", port)
	r.Run(":8080")
	if err != nil {
		log.Println("Failed to start server:", err)
	}
}
