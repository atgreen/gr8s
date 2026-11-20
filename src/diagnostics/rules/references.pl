%% SPDX-License-Identifier: MIT
%%
%% Configuration a Pod requires and does not have. Facts name objects and
%% keys only; no value of a Secret or ConfigMap is ever asserted.

:- dynamic required/8.                   % required(Pod, Location, Kind, Namespace, Name, Key, Domain, Evidence)
:- dynamic absent/4.                     % absent(Kind, Namespace, Name, Evidence)
:- dynamic key_absent/6.                 % key_absent(Kind, Namespace, Name, Key, Domain, Evidence)

%% missing(?What, ?Kind, ?Namespace, ?Name, ?Details, ?Proof)
missing("resource", Kind, Namespace, Name, [Location], [Reference, Lookup]) :-
    required(_, Location, Kind, Namespace, Name, _, _, Reference),
    absent(Kind, Namespace, Name, Lookup).
missing("key", Kind, Namespace, Name, [Key, Location], [Reference, Lookup]) :-
    required(_, Location, Kind, Namespace, Name, Key, Domain, Reference),
    key_absent(Kind, Namespace, Name, Key, Domain, Lookup).
