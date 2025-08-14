package servegin

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"laughing-octo-goggles/main.go/mongodb"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/subosito/gotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func AddUserRoutes(userCollection *mongo.Collection, r *gin.Engine) {
	// Public routes
	r.POST("/register", func(c *gin.Context) { CreateUser(userCollection, c) })
	r.POST("/login", func(c *gin.Context) { AuthenticateUser(userCollection, c) })

	// Protected routes
	protected := r.Group("/", AuthMiddleware())
	{
		protected.GET("/users", func(c *gin.Context) { GetUsers(userCollection, c) })
		protected.GET("/users/:id", func(c *gin.Context) { GetUser(userCollection, c) })
		protected.PUT("/users/:id", func(c *gin.Context) { UpdateUser(userCollection, c) })
		protected.DELETE("/users/:id", func(c *gin.Context) { DeleteUser(userCollection, c) })
	}
}

// CreateUser - POST /users (public)
func CreateUser(userCollection *mongo.Collection, c *gin.Context) {
	var user mongodb.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.ID = primitive.NewObjectID()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// AuthenticateUser - POST /auth/login (public)
func AuthenticateUser(userCollection *mongo.Collection, c *gin.Context) {

	err := gotenv.Load("./.env")
	if err != nil {
		log.Println("Error loading .env file:", err)
	}
	secret := os.Getenv("SECRET")
	if secret == "" {
		log.Fatalln("SECRET environment variable not set")
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user
	var user mongodb.User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = userCollection.FindOne(ctx, bson.M{"email": creds.Email, "password": creds.Password}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID.Hex(),
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 1 day expiry
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// GetUsers - GET /users
func GetUsers(userCollection *mongo.Collection, c *gin.Context) {
	var users []mongodb.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := userCollection.Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var user mongodb.User
		cursor.Decode(&user)
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

// GetUser - GET /users/:id
func GetUser(userCollection *mongo.Collection, c *gin.Context) {
	idParam := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var user mongodb.User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateUser - PUT /users/:id
func UpdateUser(userCollection *mongo.Collection, c *gin.Context) {
	idParam := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var updateData mongodb.User
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{"$set": bson.M{
		"name":     updateData.Name,
		"email":    updateData.Email,
		"password": updateData.Password,
	}}

	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated"})
}

// DeleteUser - DELETE /users/:id
func DeleteUser(userCollection *mongo.Collection, c *gin.Context) {
	idParam := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = userCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}
