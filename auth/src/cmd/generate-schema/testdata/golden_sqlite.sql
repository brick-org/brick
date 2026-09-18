create table "app_users" (
	"id" text PRIMARY KEY NOT NULL,
	"age" integer,
	"created_at" date NOT NULL,
	"email" text NOT NULL UNIQUE,
	"email_verified" integer NOT NULL DEFAULT 0,
	"image" text,
	"name" text NOT NULL,
	"updated_at" date NOT NULL
);

create table "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"created_at" date NOT NULL,
	"expires_at" date NOT NULL,
	"ip_address" text,
	"token" text NOT NULL UNIQUE,
	"updated_at" date NOT NULL,
	"user_agent" text,
	"user_id" text NOT NULL REFERENCES "app_users" ("id") ON DELETE CASCADE
);

create table "organizations" (
	"id" text PRIMARY KEY NOT NULL,
	"created_at" date NOT NULL,
	"metadata" text,
	"name" text NOT NULL,
	"seats" integer NOT NULL DEFAULT 5,
	"slug" text NOT NULL UNIQUE
);

create table "members" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL REFERENCES "organizations" ("id") ON DELETE CASCADE,
	"role" text NOT NULL DEFAULT 'member',
	"user_id" text NOT NULL REFERENCES "app_users" ("id") ON DELETE CASCADE
);

create index "members_organization_id_idx" on "members" ("organization_id");

create unique index "members_organization_id_user_id_uidx" on "members" ("organization_id", "user_id");

create index "members_user_id_idx" on "members" ("user_id");

create index "sessions_user_id_idx" on "sessions" ("user_id");
