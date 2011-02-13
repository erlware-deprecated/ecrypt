%%%-------------------------------------------------------------------
%%% @author Erlware <core@erlware.org>
%%% @copyright (C) 2008-2011, Erlware
%%% @doc
%%%  A pure Erlang version of the RSA public key cryptography algorithm.
%%% @end
%%%-------------------------------------------------------------------
-module(ecrypt).

%% API
-export([
         keygen/0,
         keygen/1,
         keygen/2,
         encrypt/3,
         decrypt/3,
	 primes/1,
         prime/1,
         is_prime/1,
         coprime/2,
         small_coprime/1,
         floor/1,
         exp_mod/3,
         gcd/2,
         extended_gcd/2
        ]).

-include_lib("eunit/include/eunit.hrl").

-define(SMALL_PRIMES, [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%%  Generate rsa public and private keys. The primes chose to do the generation should be of a length
%%  specified by Digits.
%% @end
%%--------------------------------------------------------------------
-spec keygen(Digits::[integer()]) -> {ok, {{public_key, {N::integer(), E::integer()}}, {private_key, {N::integer(), D::integer()}}, {max_message_size, Bytes::[byte()]}}}.
keygen(Digits) ->
    P = prime(Digits),
    Q = prime(Digits),
    case keygen(P, Q) of
	{error, {negative_private_key_exponent, _}} -> keygen(Digits);
	Keys                                        -> Keys
    end.

keygen() ->
    keygen(64).

%%--------------------------------------------------------------------
%% @doc
%%  Generate rsa public and private keys. Key gen needs as input two prime numbers P and Q
%% @end
%%--------------------------------------------------------------------
-spec keygen(P::integer(), Q::integer()) -> {ok, {{public_key, {N::integer(), E::integer()}}, {private_key, {N::integer(), D::integer()}}, {max_message_size, Bytes::[byte()]}}} | {error, Reason::string()}.
keygen(P, Q) ->
    N = P * Q,
    % Compute the Eulers Totient of two primes
    TN = (P - 1) * (Q - 1),
    E = small_coprime(TN),
    case extended_gcd(E, TN) of
	{D, _} when D < 0 ->
	    %% @todo Find out if this can be prevented. Is there a better way to pick primes. What about Rabin-Miller?
	    {error, {negative_private_key_exponent,
		     "the primes chosen produced a negative value for d - please pick new primes"}};
	{D, _} ->
	    {ok, {{public_key, {N, E}}, {private_key, {N, D}}, {max_message_size, lists:min([P, Q])}}}
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Encrypt a number.
%% @end
%%--------------------------------------------------------------------
-spec encrypt(Msg::integer(), N::integer(), E::integer()) -> integer().
encrypt(Msg, N, E) ->
    exp_mod(Msg, N, E).

%%--------------------------------------------------------------------
%% @doc
%%  Decrypt a number.
%% @end
%%--------------------------------------------------------------------
-spec decrypt(Msg::integer(), N::integer(), D::integer()) -> integer().
decrypt(Msg, N, D) ->
    exp_mod(Msg, N, D).

%% @doc
%%  Returns all prime numbers from the first prime number to N
%% @end
-spec primes(N::integer) -> [integer()].
primes(N) when N < 2 ->
    [];
primes(2) ->
    [2];
primes(N) ->
    S         = lists:seq(3, N, 2),
    MRoot     = math:sqrt(N),
    Half      = length(S),
    primeit(S, MRoot, Half).

primeit(S, MRoot, Half) ->
    primeit(3, 0, array:from_list(S, 0), MRoot, Half).

primeit(M, _I, S, MRoot, _Half) when M > MRoot ->
    [2|array:sparse_to_list(S)];
primeit(M, I, S, MRoot, Half) ->
    NewI = I + 1,
    case array:get(I, S) of
	0 ->
	    primeit(2 * NewI + 3, NewI, S, MRoot, Half);
	_Int ->
	    J    = floor((M * M - 3) / 2),
	    NS   = vacumeit(array:set(J, 0, S), M, J, Half),
	    primeit(2 * NewI + 3, NewI, NS, MRoot, Half)
    end.

vacumeit(S, _M, J, Half) when J >= Half ->
    S;
vacumeit(S, M, J, Half) ->
    vacumeit(array:set(J, 0, S), M, J + M, Half).

%%--------------------------------------------------------------------
%% @doc
%%  Generate a prime of requiring N number of bytes to represent or that is N decimal digits long.
%% @end
%%--------------------------------------------------------------------
-spec prime(N::integer(), Type::[integer()] | [byte()]) -> integer().
prime(N, Type) ->
    TestPrime = random_odd_integer(N, Type),
    prime1(TestPrime).

-spec prime(N::integer()) -> integer().
prime(N) ->
    prime(N, digits).

prime1(PrimeCandidate) ->
    case is_prime(PrimeCandidate) of
	true  -> PrimeCandidate;
	false -> prime1(PrimeCandidate + 2)
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Returns the highest integer less than or equal to the number N.
%% @end
%%--------------------------------------------------------------------
-spec floor(N::float()) -> integer.
floor(N) ->
    case round(N) of
	RN when RN =< N -> RN;
	RN -> RN - 1
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Find the smallest coprime number less than N.
%% @end
%%--------------------------------------------------------------------
-spec small_coprime(N::integer()) -> integer().
small_coprime(N) ->
    coprime(N, 2).

%%--------------------------------------------------------------------
%% @doc
%%  Find a coprime number less than N and greater than E.
%% @end
%%--------------------------------------------------------------------
-spec coprime(N::integer(), E::integer()) -> integer().
coprime(N, E) ->
    case gcd(N, E) of
	1 -> E;
	_ -> coprime(N, E + 1)
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Expoentiation modulus; Msg ^ P mod N.
%% @end
%%--------------------------------------------------------------------
-spec exp_mod(Msg::integer(), N::integer(), P::integer()) -> integer().
exp_mod(Msg, N, P) ->
    exp_mod1(Msg, N, P) rem N.

exp_mod1(Msg, _N, 1) ->
    Msg;
exp_mod1(Msg, N, P) ->
    case P rem 2 of
	0 -> exp_mod1((Msg * Msg) rem N, N, P div 2);
	1 -> Msg * exp_mod1(Msg, N, P - 1)
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Find the greatest common divisor of two numbers A an B
%% @end
%%--------------------------------------------------------------------
-spec gcd(A::integer(), B::integer()) -> integer().
gcd(A, B) when A < B ->
    gcd(B, A);
gcd(A, 0) ->
    A;
gcd(A, B) ->
    gcd(B, A rem B).

%%--------------------------------------------------------------------
%% @doc
%%  Find numbers X and Y such that AX + BY = gcd(A, B)
%% @end
%%--------------------------------------------------------------------
-spec extended_gcd(A::integer(), B::integer()) -> {X::integer(), Y::integer()}.
extended_gcd(A, B) ->
    case A rem B of
       0 ->
	    {0, 1};
       N ->
	    {X, Y} = extended_gcd(B, N),
	    {Y, X-Y*(A div B)}
    end.

%%--------------------------------------------------------------------
%% @doc
%%  Determine if a number is prime
%%  See http://en.wikipedia.org/wiki/Fermat%27s_little_theorem for explanation of this algorithm
%% @end
%%--------------------------------------------------------------------
-spec is_prime(N::integer()) -> boolean().
is_prime(D) when D > 9, D < 100 ->
    lists:member(D, lists:nthtail(4, ?SMALL_PRIMES));
is_prime(D) when D < 10 ->
    lists:member(D, [2,3,5,7]);
is_prime(D) ->
    is_prime(D, 50).

is_prime(D, I) ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    Digits = length(integer_to_list(D)) -1,
    is_prime(D, I, Digits).

is_prime(_, 0, _) ->
    true;
is_prime(N, I, Digits) ->
    case random_odd_integer(random:uniform(Digits), digits) of
	CoPrime when CoPrime < N ->
	    case exp_mod(CoPrime,N,N) of
		CoPrime -> is_prime(N, I - 1, Digits);
		_       -> false
	    end;
	_ ->
	    is_prime(N, I, Digits)
    end.


%%%===================================================================
%%% Internal functions
%%%===================================================================
random_odd_integer(Digits, digits) ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    list_to_integer(random_odd_integer_digits(Digits));
random_odd_integer(Bytes, bytes) ->
    Bits = Bytes * 8,
    <<Int:Bits>> = random_odd_binary(Bytes),
    Int.

random_odd_integer_digits(0) ->
    integer_to_list(random:uniform(5) * 2 - 1);
random_odd_integer_digits(Digits) ->
    lists:flatten([integer_to_list(random:uniform(9))|random_odd_integer_digits(Digits - 1)]).

random_odd_binary(Bytes) ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    random_odd_binary(Bytes, <<255>>).

random_odd_binary(1, <<255>>) ->
    <<255>>;
random_odd_binary(2, Acc) ->
    <<Acc/binary, 1>>;
random_odd_binary(Bytes, Acc) ->
    random_odd_binary(Bytes - 1, <<Acc/binary, (random:uniform(255))>>).


%%%===================================================================
%%% Test functions
%%%===================================================================
decrypt_test() ->
    Code = encrypt(4, 6097, 7),
    ?assertMatch(4, decrypt(Code, 6097, 4243)).

%full_rsa_test() ->
%    {ok, {{_, {N, E}}, {_, {N, D}}, _}} = keygen(500),
%    Code = encrypt(1, N, E),
%    ?assertMatch(1, decrypt(Code, N, D)).

is_prime_test() ->
    ?assertMatch(true, is_prime(671998030559713968361666935769)),
    ?assertMatch(false, is_prime(671998030559713968361666935763)).

floor_test() ->
    ?assertMatch(7, floor(7.4)),
    ?assertMatch(-8, floor(-7.4)),
    ?assertMatch(7, floor(7.0)),
    ?assertMatch(7, floor(7)),
    ?assertMatch(0, floor(0.8)).
