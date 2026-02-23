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

type DB struct {
	client     *dynamodb.Client
	usersTable string
	linksTable string
}

func New(client *dynamodb.Client, usersTable, linksTable string) *DB {
	return &DB{client: client, usersTable: usersTable, linksTable: linksTable}
}

// --- Users ---

func (d *DB) EnsureAdminUser(ctx context.Context, email string) error {
	if email == "" {
		return nil
	}
	now := time.Now().Format(time.RFC3339)
	_, err := d.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(d.usersTable),
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

func (d *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	res, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.usersTable),
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

func (d *DB) ListAllUsers(ctx context.Context) ([]User, error) {
	res, err := d.client.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(d.usersTable)})
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

func (d *DB) AddUser(ctx context.Context, email string) error {
	_, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.usersTable),
		Item: map[string]types.AttributeValue{
			"email":       &types.AttributeValueMemberS{Value: email},
			"permissions": &types.AttributeValueMemberN{Value: "0"},
			"createdAt":   &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	})
	return err
}

func (d *DB) DeleteUser(ctx context.Context, email string) error {
	_, err := d.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(d.usersTable),
		Key:       map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
	})
	return err
}

// --- Magic Links ---

func (d *DB) CheckCooldown(ctx context.Context, email string) (bool, error) {
	cutoff := time.Now().Add(-60 * time.Second).Format(time.RFC3339)
	res, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(d.linksTable),
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

func (d *DB) CreateMagicLink(ctx context.Context, email, token string, expiresAt time.Time) error {
	_, err := d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.linksTable),
		Item: map[string]types.AttributeValue{
			"token":     &types.AttributeValueMemberS{Value: token},
			"email":     &types.AttributeValueMemberS{Value: email},
			"createdAt": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			"expiresAt": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt.Unix())},
		},
	})
	return err
}

func (d *DB) GetMagicLink(ctx context.Context, token string) (*MagicLink, error) {
	res, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.linksTable),
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

func (d *DB) MarkMagicLinkUsed(ctx context.Context, token string) error {
	_, err := d.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.linksTable),
		Key:                       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
		UpdateExpression:          aws.String("SET usedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)}},
	})
	return err
}
