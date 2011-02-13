%%% -*- mode:erlang -*-
{application, ecrypt,
 [
  % A quick description of the application.
  {description, "Provides cryptographic functionality written in pure Erlang i.e no dependency on non-erlang code."},

  % The version of the applicaton
  {vsn, "0.1.0"},

  % All modules used by the application.
  {modules,
   [
    ecrypt
   ]},

  % All of the registered names the application uses.
  {registered, []},

  {applications,
   [
    kernel, 
    stdlib
   ]},

  {included_applications, []},

  % configuration parameters
  {env, []}

 ]
}.
