create table "app_users" (
	"id" text PRIMARY KEY NOT NULL,
	"age" integer,
	"created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"email" text NOT NULL UNIQUE,
	"email_verified" boolean NOT NULL DEFAULT false,
	"image" text,
	"name" text NOT NULL,
	"updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"expires_at" timestamptz NOT NULL,
	"ip_address" text,
	"token" text NOT NULL UNIQUE,
	"updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"user_agent" text,
	"user_id" text NOT NULL REFERENCES "app_users" ("id") ON DELETE CASCADE
);

create table "organizations" (
	"id" text PRIMARY KEY NOT NULL,
	"created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"metadata" jsonb,
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
