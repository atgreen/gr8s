%% SPDX-License-Identifier: MIT
%%
%% What the doctor knows about particular programs. A rule here reads only
%% what a generic rule has already shown: what a probe reported, or whether
%% mounted configuration mentions a setting. It never keeps the text itself.

%% known_application(?ImagePrefix, ?Command, ?LabelPrefix, ?Name): a program
%% recognised by its image name, the command that administers it, and the
%% prefix of the labels it sets on its own Pod.
known_application("openbao", "bao", "openbao-", "OpenBao").
known_application("vault", "vault", "vault-", "Vault").
known_application("coredns", "", "", "CoreDNS").
known_application("etcd", "etcdctl", "", "etcd").
known_application("postgres", "psql", "", "PostgreSQL").
known_application("redis", "redis-cli", "", "Redis").
known_application("valkey", "valkey-cli", "", "Redis").

%% labels_itself(?Name, ?Setting): the application labels its own Pods only
%% when its configuration mentions Setting.
labels_itself("OpenBao", "service_registration").
labels_itself("Vault", "service_registration").

:- dynamic runs/3.                       % runs(Container, Name, Command)
:- dynamic reports/3.                    % reports(Container, Key, Value), from a status listing

%% application_finding(?Code, ?Container, ?Name, ?Command)
application_finding("openbao-uninitialized", Container, Name, Command) :-
    runs(Container, Name, Command),
    reports(Container, "Initialized", "false").
application_finding("openbao-sealed", Container, Name, Command) :-
    runs(Container, Name, Command),
    reports(Container, "Initialized", "true"),
    reports(Container, "Sealed", "true").

%% remedy(?Code, ?Summary, ?Step, ?Arguments): Summary takes the Pod's name,
%% the application's name and the container; each of Arguments follows the
%% application's command in a suggested command line.
remedy("openbao-uninitialized",
       "Pod ~A: ~A in container ~S has never been initialised, so it is sealed and reports that it is not ready.",
       "Initialise it and keep the unseal keys and root token that prints, then unseal it: run the unseal command once for each key share its threshold asks for, three unless init was told otherwise.",
       ["operator init", "operator unseal"]).
remedy("openbao-sealed",
       "Pod ~A: ~A in container ~S is sealed, so it reports that it is not ready.",
       "Unseal it with enough key shares to meet its threshold.",
       ["operator unseal"]).

%% What a known application writes before it gives up.
%% said(?Code, ?Name, ?Phrase): a line holding Phrase, from the application
%% Name, means the finding Code. Only phrases that mean one thing belong here.
said("coredns-loop", "CoreDNS", "Loop (").
said("etcd-already-bootstrapped", "etcd", "has already been bootstrapped").
said("etcd-cluster-mismatch", "etcd", "cluster ID mismatch").
said("etcd-no-space", "etcd", "database space exceeded").
said("postgres-wrong-ownership", "PostgreSQL", "has wrong ownership").
said("postgres-wrong-permissions", "PostgreSQL", "has invalid permissions").
said("postgres-version-mismatch", "PostgreSQL", "database files are incompatible with server").
said("postgres-no-checkpoint", "PostgreSQL", "could not locate a valid checkpoint record").
said("redis-newer-data", "Redis", "Can't handle RDB format version").
said("redis-bad-append-file", "Redis", "Bad file format reading the append only file").

%% An evidence clause for rules/logs.pl: the container must run that application.
evidence(Code, Container, []) :-
    runs(Container, Name, _),
    said(Code, Name, Phrase),
    wrote(Container, Line),
    mentions(Line, Phrase).

log_explanation("coredns-loop",
                "Pod ~A: CoreDNS in container ~S stops because it found a forwarding loop: its upstream resolver sends queries back to it.",
                "Point CoreDNS's forward plugin at real upstream resolvers. The usual cause is a node whose /etc/resolv.conf names a local stub such as 127.0.0.53.").
log_explanation("etcd-already-bootstrapped",
                "Pod ~A: etcd in container ~S refuses to start because its data directory belongs to a member that was already bootstrapped under different settings.",
                "Start it with the settings the data was created with (initial-cluster-state=existing), or remove the member and its data and add it again.").
log_explanation("etcd-cluster-mismatch",
                "Pod ~A: etcd in container ~S is refused by its peers: its data belongs to a different cluster.",
                "This member's data directory is from another cluster. Remove the member, clear its data and add it again.").
log_explanation("etcd-no-space",
                "Pod ~A: etcd in container ~S has reached its storage quota and refuses writes.",
                "Compact and defragment etcd, then clear the NOSPACE alarm; raise the quota if the data is legitimately that large.").
log_explanation("postgres-wrong-ownership",
                "Pod ~A: PostgreSQL in container ~S refuses to start because its data directory is not owned by the user it runs as.",
                "Make the volume's owner match the container's user, for example with fsGroup or an init container that sets ownership.").
log_explanation("postgres-wrong-permissions",
                "Pod ~A: PostgreSQL in container ~S refuses to start because its data directory is readable by others.",
                "Set the data directory's mode to 0700 or 0750, which is what PostgreSQL accepts.").
log_explanation("postgres-version-mismatch",
                "Pod ~A: PostgreSQL in container ~S refuses to start because its data was written by a different major version.",
                "Run the image of the major version that wrote the data, or upgrade the data with pg_upgrade or a dump and restore.").
log_explanation("postgres-no-checkpoint",
                "Pod ~A: PostgreSQL in container ~S cannot start because its write-ahead log is damaged or incomplete.",
                "Restore from a backup or a replica. Resetting the log loses transactions and is a last resort.").
log_explanation("redis-newer-data",
                "Pod ~A: Redis in container ~S cannot load its data: the snapshot was written by a newer version.",
                "Run a version at least as new as the one that wrote the snapshot.").
log_explanation("redis-bad-append-file",
                "Pod ~A: Redis in container ~S cannot load its data: the append-only file is damaged.",
                "Repair the file with redis-check-aof, or restore it from a backup.").
