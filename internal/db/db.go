package db

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const PermAdmin = 1

type User struct {
	Email       string
	Permissions int
	CreatedAt   string
}

func (u User) IsAdmin() bool { return u.Permissions&PermAdmin != 0 }

type MagicLink struct {
	Token     string
	Email     string
	CreatedAt string
	ExpiresAt int64
	UsedAt    string
}

// --- Users ---

func EnsureAdminUser(ctx context.Context, client *dynamodb.Client, table, email string) error {
	if email == "" {
		return nil
	}
	now := time.Now().Format(time.RFC3339)
	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(table),
		Key:              map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
		UpdateExpression: aws.String("SET #perm = :perm, createdAt = if_not_exists(createdAt, :now)"),
		ExpressionAttributeNames: map[string]string{
			"#perm": "permissions",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":perm": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", PermAdmin)},
			":now":  &types.AttributeValueMemberS{Value: now},
		},
	})
	return err
}

func GetUserByEmail(ctx context.Context, client *dynamodb.Client, table, email string) (*User, error) {
	res, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
	})
	if err != nil || res.Item == nil {
		return nil, err
	}
	u := &User{Email: email}
	if v, ok := res.Item["permissions"].(*types.AttributeValueMemberN); ok {
		fmt.Sscanf(v.Value, "%d", &u.Permissions)
	}
	if v, ok := res.Item["createdAt"].(*types.AttributeValueMemberS); ok {
		u.CreatedAt = v.Value
	}
	return u, nil
}

func ListAllUsers(ctx context.Context, client *dynamodb.Client, table string) ([]User, error) {
	res, err := client.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(table)})
	if err != nil {
		return nil, err
	}
	users := []User{}
	for _, item := range res.Items {
		u := User{}
		if v, ok := item["email"].(*types.AttributeValueMemberS); ok {
			u.Email = v.Value
		}
		if v, ok := item["permissions"].(*types.AttributeValueMemberN); ok {
			fmt.Sscanf(v.Value, "%d", &u.Permissions)
		}
		if v, ok := item["createdAt"].(*types.AttributeValueMemberS); ok {
			u.CreatedAt = v.Value
		}
		users = append(users, u)
	}
	return users, nil
}

func AddUser(ctx context.Context, client *dynamodb.Client, table, email string) error {
	_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item: map[string]types.AttributeValue{
			"email":       &types.AttributeValueMemberS{Value: email},
			"permissions": &types.AttributeValueMemberN{Value: "0"},
			"createdAt":   &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})
	return err
}

func DeleteUser(ctx context.Context, client *dynamodb.Client, table, email string) error {
	_, err := client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
	})
	return err
}

// --- Magic Links ---

func CheckCooldown(ctx context.Context, client *dynamodb.Client, table, email string) (bool, error) {
	cutoff := time.Now().Add(-60 * time.Second).Format(time.RFC3339)
	res, err := client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(table),
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email AND createdAt > :cutoff"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email":  &types.AttributeValueMemberS{Value: email},
			":cutoff": &types.AttributeValueMemberS{Value: cutoff},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return false, err
	}
	return len(res.Items) > 0, nil
}

func CreateMagicLink(ctx context.Context, client *dynamodb.Client, table, email, token string, expiresAt time.Time) error {
	_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item: map[string]types.AttributeValue{
			"token":     &types.AttributeValueMemberS{Value: token},
			"email":     &types.AttributeValueMemberS{Value: email},
			"createdAt": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			"expiresAt": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt.Unix())},
		},
	})
	return err
}

func GetMagicLink(ctx context.Context, client *dynamodb.Client, table, token string) (*MagicLink, error) {
	res, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
	})
	if err != nil || res.Item == nil {
		return nil, err
	}
	ml := &MagicLink{Token: token}
	if v, ok := res.Item["email"].(*types.AttributeValueMemberS); ok {
		ml.Email = v.Value
	}
	if v, ok := res.Item["expiresAt"].(*types.AttributeValueMemberN); ok {
		fmt.Sscanf(v.Value, "%d", &ml.ExpiresAt)
	}
	if v, ok := res.Item["usedAt"].(*types.AttributeValueMemberS); ok {
		ml.UsedAt = v.Value
	}
	return ml, nil
}

func MarkMagicLinkUsed(ctx context.Context, client *dynamodb.Client, table, token string) error {
	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(table),
		Key:                       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
		UpdateExpression:          aws.String("SET usedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)}},
	})
	return err
}
