%% SPDX-License-Identifier: MIT
%%
%% Why the API refused a ServiceAccount. A program that is refused writes
%% what it was refused; these rules read the bindings and roles to say which
%% link is missing: no binding, a role without the verb, or a role that does
%% not mention the resource.

%% denied(?Container, ?Account, ?Verb, ?Group, ?Resource, ?Scope), from a line such as
%%   pods is forbidden: User "system:serviceaccount:monitoring:ksm" cannot list
%%   resource "pods" in API group "" at the cluster scope
%% Scope is cluster or namespace(Name). Quotes may be escaped, as in JSON logs.
denied(Container, account(Namespace, Name), Verb, Group, Resource, Scope) :-
    wrote(Container, Line),
    mentions(Line, "is forbidden: User "),
    split_string(Line, "\"", "\\", Parts),
    append(_, [Before, User, Action, Resource, _, Group, Where|Rest], Parts),
    sub_string(Before, _, _, 0, "forbidden: User "),
    split_string(User, ":", "", ["system", "serviceaccount", Namespace, Name]),
    split_string(Action, " ", "", Words),
    append(_, ["cannot", Verb, "resource"|_], Words),
    scope(Where, Rest, Scope),
    !.

scope(Where, _, cluster) :- mentions(Where, "cluster scope"), !.
scope(Where, [Namespace|_], namespace(Namespace)) :- mentions(Where, "in the namespace").

asks(access(Scope)) :- denied(_, _, _, _, _, Scope).

%% What the cluster holds, asserted in answer to access(Scope).
:- dynamic binding/4.                    % binding(Id, Where, RoleKind, RoleName): Where is cluster or a namespace
:- dynamic subject/4.                    % subject(Binding, Kind, Namespace, Name)
:- dynamic grants/6.                     % grants(RoleKind, RoleNamespace, RoleName, Verbs, Groups, Resources)
:- dynamic access_unknown/0.             % the bindings or roles could not be read

%% access_finding(?Code, ?Container, ?Details). Nothing is concluded when the
%% roles do allow the request: the refusal is then older than the roles, or
%% comes from something these rules do not read.
access_finding(Code, Container, [Who, Verb, What, Place|More]) :-
    crashed_container(Container),
    once(denied(Container, Account, Verb, Group, Resource, Scope)),
    \+ access_unknown,
    \+ permitted(Account, Verb, Group, Resource, Scope),
    shortfall(Code, Account, Group, Resource, Scope, More),
    described(Account, Group, Resource, Scope, Who, What, Place).

shortfall("access-not-bound", Account, _, _, Scope, []) :-
    \+ bound(Account, Scope, _),
    !.
shortfall("access-verb-missing", Account, Group, Resource, Scope, [Roles]) :-
    findall(Name, ( bound(Account, Scope, Role), mentions_resource(Role, Group, Resource), role_name(Role, Name) ),
            Found),
    Found \== [],
    !,
    sort(Found, Roles).
shortfall("access-not-granted", Account, _, _, Scope, [Roles]) :-
    findall(Name, ( bound(Account, Scope, Role), role_name(Role, Name) ), Found),
    sort(Found, Roles).

permitted(Account, Verb, Group, Resource, Scope) :-
    bound(Account, Scope, Role),
    allows(Role, Verb, Group, Resource).

%% bound(+Account, +Scope, ?Role): a binding that reaches Scope gives Account the Role.
bound(account(Namespace, Name), Scope, role(Kind, Home, RoleName)) :-
    binding(Binding, Where, Kind, RoleName),
    reaches(Where, Scope),
    names(Binding, Namespace, Name),
    role_home(Kind, Where, Home).

%% A ClusterRoleBinding reaches everything; a RoleBinding its own namespace.
reaches(cluster, _) :- !.
reaches(Namespace, namespace(Namespace)).

names(Binding, Namespace, Name) :- subject(Binding, "ServiceAccount", Namespace, Name).
names(Binding, Namespace, _) :- subject(Binding, "Group", _, Group), account_group(Namespace, Group).

account_group(_, "system:serviceaccounts").
account_group(_, "system:authenticated").
account_group(Namespace, Group) :- string_concat("system:serviceaccounts:", Namespace, Group).

%% A ClusterRole has no namespace; a Role lives where its binding does.
role_home("ClusterRole", _, "").
role_home("Role", Namespace, Namespace).

allows(role(Kind, Home, Name), Verb, Group, Resource) :-
    grants(Kind, Home, Name, Verbs, Groups, Resources),
    covers(Verbs, Verb), covers(Groups, Group), covers(Resources, Resource).

mentions_resource(role(Kind, Home, Name), Group, Resource) :-
    grants(Kind, Home, Name, _, Groups, Resources),
    covers(Groups, Group), covers(Resources, Resource).

covers(List, _) :- memberchk("*", List), !.
covers(List, Item) :- memberchk(Item, List).

role_name(role(Kind, _, Name), Text) :- string_concat(Kind, " ", Prefix), string_concat(Prefix, Name, Text).

described(account(Namespace, Name), Group, Resource, Scope, Who, What, Place) :-
    string_concat(Namespace, "/", Prefix), string_concat(Prefix, Name, Who),
    ( Group == "" -> What = Resource
    ; string_concat(Resource, ".", Dotted), string_concat(Dotted, Group, What) ),
    ( Scope = namespace(In) -> string_concat("in namespace ", In, Place) ; Place = "in any namespace" ).

%% access_explanation(?Code, ?Summary, ?Step): Summary takes the Pod's name,
%% the container, the account, the verb, the resource, the place and, for
%% all but the first, the roles.
access_explanation("access-not-bound",
                   "Pod ~A: container ~S is refused by the API: ServiceAccount ~A may not ~A ~A ~A, and no RoleBinding or ClusterRoleBinding gives it a role there.",
                   "Bind the ServiceAccount to a role that allows this. A chart usually creates the binding; check that it was installed and names this ServiceAccount and namespace.").
access_explanation("access-verb-missing",
                   "Pod ~A: container ~S is refused by the API: ServiceAccount ~A may not ~A ~A ~A. It is bound to ~{~A~^, ~}, where a rule covers that resource but none gives that verb.",
                   "Add the verb to the role's rule for that resource.").
access_explanation("access-not-granted",
                   "Pod ~A: container ~S is refused by the API: ServiceAccount ~A may not ~A ~A ~A. It is bound to ~{~A~^, ~}, and no rule there covers that resource.",
                   "Add a rule for that resource to one of the roles, or bind the ServiceAccount to a role that has one.").
