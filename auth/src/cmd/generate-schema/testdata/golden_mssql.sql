create table [app_users] (
	[id] varchar(36) PRIMARY KEY NOT NULL,
	[age] integer,
	[created_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
	[email] varchar(255) NOT NULL UNIQUE,
	[email_verified] smallint NOT NULL DEFAULT 0,
	[image] varchar(8000),
	[name] varchar(8000) NOT NULL,
	[updated_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table [sessions] (
	[id] varchar(36) PRIMARY KEY NOT NULL,
	[created_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
	[expires_at] datetime2(3) NOT NULL,
	[ip_address] varchar(8000),
	[token] varchar(255) NOT NULL UNIQUE,
	[updated_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
	[user_agent] varchar(8000),
	[user_id] varchar(36) NOT NULL REFERENCES [app_users] ([id]) ON DELETE CASCADE
);

create table [organizations] (
	[id] varchar(36) PRIMARY KEY NOT NULL,
	[created_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
	[metadata] varchar(8000),
	[name] varchar(8000) NOT NULL,
	[seats] integer NOT NULL DEFAULT 5,
	[slug] varchar(255) NOT NULL UNIQUE
);

create table [members] (
	[id] varchar(36) PRIMARY KEY NOT NULL,
	[organization_id] varchar(36) NOT NULL REFERENCES [organizations] ([id]) ON DELETE CASCADE,
	[role] varchar(8000) NOT NULL DEFAULT 'member',
	[user_id] varchar(36) NOT NULL REFERENCES [app_users] ([id]) ON DELETE CASCADE
);

create index [members_organization_id_idx] on [members] ([organization_id]);

create unique index [members_organization_id_user_id_uidx] on [members] ([organization_id], [user_id]);

create index [members_user_id_idx] on [members] ([user_id]);

create index [sessions_user_id_idx] on [sessions] ([user_id]);
