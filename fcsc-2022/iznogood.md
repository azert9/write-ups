# Iznogood

*This write-up is for the "IZNOGOOD" challenge of [FCSC 2022](https://france-cybersecurity-challenge.fr). Two files are given: a python script and an output.*

A poor intern had the very bad idea to implement its own cryptography. How can we prove him this is a bad idea?

## Understanding the Cipher
Let's take a look at the source code:

```python
KP = 1
flag = open("flag.txt", "rb").read()

k = os.urandom(16)
E = IZNOGOOD(k)

P = [ flag[i:i+16] for i in range(0, len(flag), 16) ]
C = [ E.encrypt(p) for p in P ]

for i in range(len(P)):
    if i < KP: print(P[i].hex(), C[i].hex())
    else:      print("?" * 32, C[i].hex())
```

Iznogood is a block cipher. We have a known (plaintext ; ciphertext) pair, and some additional blocks of ciphertext with that juicy flag encrypted.

```python
class IZNOGOOD:
    def __init__(self, k):
        self.k = self._b2n(k)
        self.nr = 8
        self.S = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
        self.pi = [
            [0x2,0x4,0x3,0xf,0x6,0xa,0x8,0x8,0x8,0x5,0xa,0x3,0x0,0x8,0xd,0x3,
             0x1,0x3,0x1,0x9,0x8,0xa,0x2,0xe,0x0,0x3,0x7,0x0,0x7,0x3,0x4,0x4],
            [0xa,0x4,0x0,0x9,0x3,0x8,0x2,0x2,0x2,0x9,0x9,0xf,0x3,0x1,0xd,0x0,
             0x0,0x8,0x2,0xe,0xf,0xa,0x9,0x8,0xe,0xc,0x4,0xe,0x6,0xc,0x8,0x9],
            [0x4,0x5,0x2,0x8,0x2,0x1,0xe,0x6,0x3,0x8,0xd,0x0,0x1,0x3,0x7,0x7,
             0xb,0xe,0x5,0x4,0x6,0x6,0xc,0xf,0x3,0x4,0xe,0x9,0x0,0xc,0x6,0xc],
            [0xc,0x0,0xa,0xc,0x2,0x9,0xb,0x7,0xc,0x9,0x7,0xc,0x5,0x0,0xd,0xd,
             0x3,0xf,0x8,0x4,0xd,0x5,0xb,0x5,0xb,0x5,0x4,0x7,0x0,0x9,0x1,0x7],
            [0x9,0x2,0x1,0x6,0xd,0x5,0xd,0x9,0x8,0x9,0x7,0x9,0xf,0xb,0x1,0xb,
             0xd,0x1,0x3,0x1,0x0,0xb,0xa,0x6,0x9,0x8,0xd,0xf,0xb,0x5,0xa,0xc],
            [0x2,0xf,0xf,0xd,0x7,0x2,0xd,0xb,0xd,0x0,0x1,0xa,0xd,0xf,0xb,0x7,
             0xb,0x8,0xe,0x1,0xa,0xf,0xe,0xd,0x6,0xa,0x2,0x6,0x7,0xe,0x9,0x6],
            [0xb,0xa,0x7,0xc,0x9,0x0,0x4,0x5,0xf,0x1,0x2,0xc,0x7,0xf,0x9,0x9,
             0x2,0x4,0xa,0x1,0x9,0x9,0x4,0x7,0xb,0x3,0x9,0x1,0x6,0xc,0xf,0x7],
            [0x0,0x8,0x0,0x1,0xf,0x2,0xe,0x2,0x8,0x5,0x8,0xe,0xf,0xc,0x1,0x6,
             0x6,0x3,0x6,0x9,0x2,0x0,0xd,0x8,0x7,0x1,0x5,0x7,0x4,0xe,0x6,0x9],
            [0xa,0x4,0x5,0x8,0xf,0xe,0xa,0x3,0xf,0x4,0x9,0x3,0x3,0xd,0x7,0xe,
             0x0,0xd,0x9,0x5,0x7,0x4,0x8,0xf,0x7,0x2,0x8,0xe,0xb,0x6,0x5,0x8],
        ]
        self.rk = self.pi
        for r in range(self.nr + 1):
            for i in range(32):
                self.rk[r][i] ^= self.k[i]
```

The cipher is initialized with several values, which we will understand later.

```python
def encrypt(self, m):
    s = self._b2n(m)
    for i in range (self.nr - 1):
        s = self._addKey(s, i)
        s = self._S(s)
        s = self._P(s)
    s = self._addKey(s, self.nr - 1)
    s = self._S(s)
    s = self._addKey(s, self.nr)
    return self._n2b(s)
```

Looking at the `encrypt` method, we identify that Iznogood is a [Substitution–permutation network](https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network), juste like AES. Must be super secure then?

The state `s` is initialized from the ciphertext after undergoing a transformation:

```python
def _n2b(self, v):
    L = []
    for i in range (0, len(v), 2):
        a, b = v[i], v[i + 1]
        L.append( b ^ (a << 4) )
    return bytes(L)

def _b2n(self, v):
    L = []
    for x in v:
        L.append( (x >> 4) & 0xf )
        L.append( x & 0xf )
    return L
```

Every byte is split into two bytes. This transformation was also applied to the key in the constructor.

```python
def _addKey(self, a, r):
    return [ x ^ y for x, y in zip(a, self.rk[r]) ]
```

The `_addKey` method does just that: the state is combined with a round key. Every round key is computed by xor-ing the key with a fixed array in `self.pi`.

```python
def _S(self, s):
    return [ self.S[x] for x in s ]
```

This method implements a "Substitution Box". Every byte is replaced by another value using the lookup table `self.S`.

```python
def _P(self, s):
    r = []
    for j in range(32):
        b = 0
        for i, x in enumerate(s):
            if i == j: continue
            b ^= x
        r.append(b)
    return r
```

The method `_P()`is a "Permutation Box". We will look deeper into this later.

```python
def encrypt(self, m):
    s = self._b2n(m)
    for i in range (self.nr - 1):
        s = self._addKey(s, i)
        s = self._S(s)
        s = self._P(s)
    s = self._addKey(s, self.nr - 1)
    s = self._S(s)
    s = self._addKey(s, self.nr)
    return self._n2b(s)
```

Stepping back to the big picture: we have a substitution permutation network, split into 8 rounds. This construct by itself seems pretty strong, so what's the problem?

## Finding the Vulnerability
A secure cipher sould have good [confusion and diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion). Every input bit must be tightly linked to every output bit, and the action of the key on the transformation should not be too obvious. This property can be achieved by repeating elementary steps several time, "mixing up" the bits at every iteration.

The only step responsible for propagating changes in between bytes is the permutation box. The other steps could be performed on every byte separatly, without communication.

```python
def _P(self, s):
    r = []
    for j in range(32):
        b = 0
        for i, x in enumerate(s):
            if i == j: continue
            b ^= x
        r.append(b)
    return r
```

Let's try to understand what is going on in this P-box by rearranging the python code:

```python
def _P(self, s):
	constant = 0
    for x in s:
        constant ^= x
    return [x ^ constant for x in s]
```

This code is strictly equivalent to the original function, but much simpler. There is something important to note : every output byte depends solely on the corresponding input byte, and a value which is the same for every bytes.

I decided to call this value `constant` for the rest of my code. This is not a good choice of word but we needed one...

What if we could eliminate this `constant`? The the cipher would have no diffusion! It would be trivial to recover the key.

We could eliminate it if we knew its value at each of the 7 rounds where it appears.

How do we recover 7 small 4-bits values? By brute-force!

## Brute Force Attack

At this point, we will switch from python to C++, for performance reasons. 

What we want to do is:
* Enumerate all tuples of 7 4-bits values as candiates for the `constant`.
* For every tuple, brute-force every byte of the key indivudually. If this exhaustive search fails, then we can elliminate the tuple.

```c++
class BruteForce
{
public:
	struct Context
	{
		uint8_t constants[7];
		uint8_t key_nibbles[32];
	};

public:
	BruteForce(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext)
	{
		assert(plaintext.size() == 16);
		assert(ciphertext.size() == 16);

		auto tmp = b2n(plaintext);
		std::copy(tmp.begin(), tmp.end(), m_initial_state);

		tmp = b2n(ciphertext);
		std::copy(tmp.begin(), tmp.end(), m_final_state);
	}
	
	// ...

private:
	uint8_t m_initial_state[32];
	uint8_t m_final_state[32];
};
```

The `BruteForce` class contains the initial state and the final state of the cipher for our known (plaintext ; ciphertext) pair. The `Context` structure will keep track of the state of the brute-force attack.

```c++
bool brute_force_rec(Context& ctx, size_t constants_count) const noexcept
{
	if (constants_count == 7)
		return try_parameters(ctx, 0);

	bool found = false;

	for (uint8_t b = 0; b < 16; ++b)
	{
		ctx.constants[constants_count] = b;
		if (brute_force_rec(ctx, constants_count + 1))
				found = true;
	}

	return found;
}
```

`brute_force_rec` is a recursive function for enumerating all the possible tuples of values for `constant`.

```c++
bool brute_force_key_rec(Context& ctx, size_t index) const noexcept
{
    if (index == 32)
        return test_coherence(ctx);

        bool found = false;

        for (uint8_t k = 0; k < 16; ++k)
        {
			ctx.key_nibbles[index] = k;
			if (test_key_nibble(ctx, index))
			{
				if (brute_force_key_rec(ctx, index + 1))
					found = true;
			}
        }

        return found;
}
```

`brute_force_key_rec` will brute-force the key byte-by-byte. Because every byte of the key is split in two at the beginning, we are testing only 16 possibilities for every byte of the transformed key.

```c++
bool test_key_nibble(const Context& ctx, size_t index) const noexcept
{
    uint8_t state = m_initial_state[index];
    uint64_t key = ctx.key_nibbles[index];

	for (int i = 0; i < 7; ++i)
    {
        // add key
        state ^= ROUND_KEYS_XOR[i][index];
        state ^= key;

        // S-box
        state = S_BOX[state];

        // P-box
        state ^= ctx.constants[i];
	}

	// add key
	state ^= ROUND_KEYS_XOR[7][index];
	state ^= key;

	// S-box
	state = S_BOX[state];

	// add key
	state ^= ROUND_KEYS_XOR[8][index];
	state ^= key;

	return state == m_final_state[index];
}

```

`test_key_nibble` tests one byte of the key, using the given parameters. It reproduces the cipher algorithm and checks that the final state matches the expected one.

```c++
// Testing coherence over the whole block (because the "constants" depend on the key).
bool test_coherence(const Context& ctx) const noexcept
{
	uint8_t state[32];
	std::copy(m_initial_state, m_initial_state + 32, state);

	for (int i = 0; i < 7; ++i)
	{
		// add key
		for (int j = 0; j < 32; ++j)
			state[j] ^= ROUND_KEYS_XOR[i][j] ^ ctx.key_nibbles[j];

		// S-box
		for (uint8_t& b : state)
			b = S_BOX[b];

		// P-box
		if (xor_state(state) != ctx.constants[i])
			return false;
		for (uint8_t& b : state)
			b ^= ctx.constants[i] ;
	}

	// add key
	for (int j = 0; j < 32; ++j)
		state[j] ^= ROUND_KEYS_XOR[7][j] ^ ctx.key_nibbles[j];

	// S-box
	for (uint8_t& b : state)
		b = S_BOX[b];

	// add key
	for (int j = 0; j < 32; ++j)
		state[j] ^= ROUND_KEYS_XOR[8][j] ^ ctx.key_nibbles[j];

	print_result(ctx);
	assert(std::memcmp(state, m_final_state, sizeof(m_final_state)) == 0);
	return true;
}
```

When a `constants` tuple is found to be coherent accross all bytes of the state, we still don't have the guarantee that it is a valid solution. The method `test_coherence` performs an encryption using the whole key to eliminate all the possibilities with coherence issues.

```c++
void print_result(const Context& ctx) const noexcept
{
	std::cout << "[";
	for (uint8_t constant : ctx.constants)
		std::cout << (unsigned)constant << ", ";
	std::cout << "], [";
	for (uint8_t k : ctx.key_nibbles)
		std::cout << (unsigned)k << ", ";
	std::cout << "]";

	std::cout << std::endl;
}

```

When a solution is found, it is printed using the dirty function above. Because several keys may be found, it is important to print them all. 

## Run!

The algorithm is made parallel because we want to go *fast*.

```c++
bool brute_force(uint8_t first_constant) const noexcept
{
	Context ctx = {};
	ctx.constants[0] = first_constant;
	return brute_force_rec(ctx, 1);
}
```

The function `brute_force` serves as an entry point for the brute-force. We are going to call it from 16 different threads, each time with a differernt value for the first `constant`.

```c++
int main()
{
	std::vector<uint8_t> plaintext{
		70, 67, 83, 67, 123, 102, 97, 52, 50, 50, 101, 51, 51, 57, 52, 52
	};
	std::vector<uint8_t> ciphertext{
		7, 176, 211, 44, 138, 106, 37, 220, 120, 45, 46, 226, 10, 205, 83, 243
	};

	BruteForce bf(plaintext, ciphertext);

	std::vector<std::thread> threads;
	for (int i = 0; i < 16; ++i)
	{
		threads.emplace_back([&bf, i]() {
				std::cout << bf.brute_force(i) << std::endl;
		});
	}

	for (auto& thread : threads)
		thread.join();

	return 0;
}

```

Let's hit the "run" button!
```
$ time ./chal_iznogood
...
```

![Image](res/a-few-moments-later.jpg)

```
$ time ./chal_iznogood
[14, 9, 5, 4, 5, 10, 15, ], [1, 8, 13, 12, 10, 14, 14, 0, 11, 8, 15, 14, 14, 11, 13, 9, 10, 0, 11, 13, 10, 9, 3, 8, 11, 8, 12, 5, 4, 9, 2, 5, ]
[14, 9, 5, 4, 5, 10, 15, ], [1, 8, 13, 12, 10, 14, 14, 0, 15, 3, 15, 14, 7, 11, 13, 2, 10, 15, 11, 13, 2, 5, 11, 8, 11, 8, 9, 0, 4, 9, 11, 5, ]
[14, 9, 5, 4, 5, 10, 15, ], [1, 8, 13, 12, 10, 14, 15, 0, 11, 3, 9, 14, 12, 11, 13, 9, 11, 5, 11, 13, 2, 5, 8, 8, 11, 8, 12, 0, 4, 9, 8, 9, ]
[14, 9, 5, 4, 5, 10, 15, ], [1, 8, 13, 12, 10, 14, 15, 0, 11, 8, 9, 14, 13, 11, 13, 2, 10, 15, 11, 13, 10, 5, 3, 8, 11, 8, 9, 5, 4, 2, 2, 11, ]
[14, 9, 5, 4, 5, 10, 15, ], [14, 8, 2, 12, 10, 14, 14, 0, 13, 3, 15, 14, 14, 11, 13, 15, 14, 15, 11, 13, 10, 11, 8, 11, 11, 8, 9, 5, 4, 8, 11, 5, ]
./chal_iznogood  9393,04s user 3,91s system 1053% cpu 14:51,62 total
```

15 minutes later, the program terminates and we are left with a few valid combinations.

Back to python, we can test every key against the given ciphetext. We can simply copy and paste them manually one-by-one in the script. Below is the final result with the right key:

```python
k = n2b([1, 8, 13, 12, 10, 14, 15, 0, 11, 3, 9, 14, 12, 11, 13, 9, 11, 5, 11, 13, 2, 5, 8, 8, 11, 8, 12, 0, 4, 9, 8, 9, ])
E = IZNOGOOD(k)

flag = ""
for block in ["07b0d32c8a6a25dc782d2ee20acd53f3", "ba596368fc650d3d08ffbfb2bda27f28", "68be7f31b109babfb667aabb92a119cd", "acf46fe7220bf34cb2fe740c5773b354"]:
    flag += E.decrypt(bytes.fromhex(block)).decode()
print(flag)
```

```
$ python3 ./chal_iznogood.py
FCSC{fa422e339447d2665a285eb005cdf70670888d3f1ac44bb8ca054cd600}
```
