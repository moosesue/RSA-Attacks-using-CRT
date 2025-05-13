# RSA Attacks using the Chinese Remainder Theorem.

## The Chinese Remainder Theorem

The Chinese remainder theorem (CRT) says that if you know the remainders of dividing an integer $n$ by several different integers then you can also find the remainder of dividing n by the product of these integers, if none of them are a pair with a GCD other than 1. This means that there is a unique solution modulo the product of the moduli, as long as they are pairwise coprime. In cryptography, this can correspond to finding a way to break the encryption and reach the unique plaintext solution.

In other words:

Let $n$<sub>1</sub>, $n$<sub>2</sub>, $n$<sub>3</sub>,..., $n$<sub>k</sub> be integers that are each greater than or equal to 1. If none of these integers share a common divisor other than 1 then they are said to be pairwise coprime. If there are integers $a$<sub>1</sub>, $a$<sub>2</sub>, $a$<sub>3</sub>,..., $a$<sub>k</sub> where $0<=a$<sub>i</sub>$<n$<sub>i</sub> then there is only 1 solution modulo N (where N is the product of all $n$<sub>i</sub>) to:

$x \equiv a$<sub>1</sub> mod(<i>n</i><sub>1</sub>) $\equiv a$<sub>2</sub> mod(<i>n</i><sub>2</sub>) $\equiv a$<sub>3</sub> mod(<i>n</i><sub>3</sub>) $\equiv$... $\equiv a$ <sub>k</sub> mod(<i>n</i><sub>k</sub>)

In cryptographic applications, like Håstad’s Broadcast Attack, each $a$<sub>i</sub> corresponds to a ciphertext 
$c$<sub>i</sub> $= M$<sup>e</sup> mod $n$<sub>i</sub>, where $M$ is the original message and $e$ is a small 
public exponent (e.g. $e = 3$).

To reconstruct the solution using the Chinese Remainder Theorem (CRT), compute:

$x$ = $∑$ (from $i = 1$ to $k$) of $[ cᵢ * Nᵢ * mᵢ ]$ mod $N$

Where:
- cᵢ = the i-th ciphertext (i.e., Mᵉ mod nᵢ)
- nᵢ = the i-th modulus
- N = n₁ × n₂ × ... × nₖ
- Nᵢ = N / nᵢ
- mᵢ = modular inverse of Nᵢ mod nᵢ (i.e., Nᵢ × mᵢ ≡ 1 mod nᵢ)

This formula combines the separate ciphertexts into one number congruent to $Mᵉ$ mod $N$, which can be root extracted to recover $M$.

Here is the function in Python:
```python
def crt(ns, cs):
    N = 1
    for n in ns:
	#find the product of all of the n's given
        N *= n

    result = 0
    #for n1,c1 and then n2,c2 etc.
    for ni, ci in zip(ns, cs):
	#Ni = total sum divided by individual n
        Ni = N // ni
	#find the modular inverse to find Ni mod ni to give mi so Ni * mi = 1 mod ni
        mi = modular_inverse.modular_inverse(Ni, ni)
	#now add ci * Ni * mi to total as per CRT recombination
	#this is because ci * Ni * mi = ci mod ni, so the sum of these is x
        result += ci * Ni * mi
	
    #return the result mod N. This is M^e.
    return result % N
```

And in Rust:

```rust
fn crt(ns:&[u64;3],cs:&[BigUint;3])->BigUint {
    let mut N = BigUint::one();
    for n in ns{
        N *= BigUint::from(*n);
    }
    let mut result = BigUint::zero();
    
    for (i,ni) in ns.iter().enumerate(){
        let ni_big = BigUint::from(*ni);
        let Ni = &N/&ni_big;
        let mi = Ni.modinv(&ni_big).unwrap();
        result += &cs[i] * &Ni * mi;
        
        
    }
    
    result % N

}
```
## Håstad’s Broadcast Attack

The Chinese Remainder Theorem can be used to attack RSA encryption, if certain conditions are met. Håstad’s Broadcast Attack relies on the same message being sent at least $e$ times using different primes and a small value of $e$. This means that there is a unique solution to a set of congruences if you can form at least $e$ of them. The result is $M$<sup>e</sup> and on taking the $e$<sup>th</sup> root the original message can be found. We will fail if the value of $M$<sup>e</sup> is bigger than $N$ or if the integer root of $M$<sup>e</sup> is not exact. All of the values of $n$ must also be pairwise coprime.

Here is an implementation in Python of the attack using the message "test!" and 3 sets of hard coded primes.

```python
def Hastads_attack():

	#Håstad’s Broadcast Attack relies on the same message being encrypted using at least 3 
	#pairs of different prime numbers and also using a low value of e to generate the encryption keys.
	
	#pick 3 sets of prime numbers to use

	#set p1 and q1 and generate key n1
	p1,q1 = 10000139,10000141 
	#set p2 and q2 and generate key n2
	p2,q2 = 10000103,10000121
	#set p3 and q3 and generate key n3
	p3,q3 = 10000019, 10000079
	n1,n2,n3 = p1*q1, p2*q2, p3*q3
	
	#set e to be small, e.g. 3. Attack only works if e is small.
	e = 3
	#send the same message 
	#set the message
	message_bytes = b'test!'
	message_int = int.from_bytes(message_bytes,'big')

	#now use the same e, but different n to encrypt the same message.
	#encrypt it using set 1
	ciphertext1 = encrypt.rsa_encrypt(message_int,e,n1)
	#encrypt it using set 2
	ciphertext2 = encrypt.rsa_encrypt(message_int,e,n2)
	#encrypt it using set 3
	ciphertext3 = encrypt.rsa_encrypt(message_int,e,n3)
	
	#Now we can use the Chinese Remainder Theorem to bypass the decrypt function.
	
	#check that the gcd of all pairs is 1 (all moduli are pairwise coprime).
	if (gu.standard_gcd(n1,n2) != 1) or (gu.standard_gcd(n1,n3) != 1) or (gu.standard_gcd(n2,n3) != 1):
		#CRT fails
		raise ValueError("CRT failure on GCD")
	
	#M^e = C mod (n1 * n2 * n3) using the Chinese Remainder Theorem.
	ns = [n1,n2,n3]
	cs = [ciphertext1,ciphertext2,ciphertext3]
	C = crt(ns,cs)

	#find the eth root of C using function integer_nthroot
	guessed_message, exact = integer_nthroot(C,e) 
	if not exact:
		#see if C is bigger than sum_n
		sum_n = n1 * n2 * n3
		#If the root is not exact but C > n1 * n2 * n3 then m^e was too large - primes are too small
		if C > sum_n:
			print("M cubed is too big. Pick different primes.")
		else:
			print("Root not exact. Attack failed.")
		return
	else:
		guessed_bytes = guessed_message.to_bytes((guessed_message.bit_length() + 7) // 8, 'big')
		print("Raw guessed bytes:", guessed_bytes)
		try:
			print("Decoded:", guessed_bytes.decode())
			#check that the guess matches the original
			assert guessed_message == message_int, "Recovered integer does not match original!"
			print("Success! Recovered plaintext matches the original message.")
		except UnicodeDecodeError:
			print("Decode failed. Message was not correct.")
```
And here is the same attack in Rust:

```rust
fn hastads_attack(){
    //Pick 3 sets of primes.
    let (p1, q1):(u64,u64) = (10000139,10000141);
    let (p2, q2):(u64,u64) = (10000103,10000121);
    let (p3, q3):(u64,u64) = (10000019, 10000079);
    let (n1 ,n2 ,n3) = ((p1*q1), (p2*q2), (p3*q3));
    
    //set e to be small, e.g. 3
    let e = 3;
    let message: &[u8] = b"test!";
    let message_int = BigUint::from_bytes_be(message);
    
    //now use the same e, but different n to encrypt the same message.
	//encrypt it using sets 1,2,3
    let ciphertext1 = encrypt::rsa_encrypt_big(message_int.clone(),e as u32,n1.to_u64().expect("n1 too big for u64"));
    let ciphertext2 = encrypt::rsa_encrypt_big(message_int.clone(),e as u32,n2.to_u64().expect("n2 too big for u64"));
    let ciphertext3 = encrypt::rsa_encrypt_big(message_int.clone(),e as u32,n3.to_u64().expect("n3 too big for u64"));
    
    //Now we can use the Chinese Remainder Theorem to bypass the decrypt function.
	
    //check that the gcd of all pairs is 1 (all moduli are pairwise coprime).
    if (gcd_utils::standard_gcd_64(n1,n2) != 1) || (gcd_utils::standard_gcd_64(n1,n3) != 1) || 
        (gcd_utils::standard_gcd_64(n2,n3) != 1){
        //CRT fails so raise an error
        eprintln!("Error")
    }

    let ns = [n1,n2,n3];
    let cs = [ciphertext1,ciphertext2,ciphertext3];
    let C = crt(&ns,&cs);

    let guessed_message = C.nth_root(e);//integer_nth_root(&C,e);
    if guessed_message.pow(e) == C {
        match String::from_utf8(guessed_message.to_bytes_be()){
            Ok(text)=>println!("The message is :{}",text),
            Err(e)=>println!("Error converting int to text."),
        }
        
    }
	else{
        println!("Root not exact for guess: {},C: {}",guessed_message,C);
        println!("Decoding failed.");
    }
}
```
## RSA-CRT Fault Attack e.g. Bellcore Attack

The Chinese Remainder Theorem (CRT) can also be used to more efficiently decrypt the ciphertext generated using the RSA algorithm. This adaptation is referred to as RSA-CRT. RSA uses $m = c$ <sup>d</sup> mod $n$ to find plaintext $m$ from ciphertext $c$. The computational complexity of this is determined by the number of bits in $d$ and $n$ as computing the exponentiation is usually found using square and multiply methods (i.e. finding the square and then multiplying this the required number of times before possibly multiplying the number by itself again if the exponent is odd). CRT can be used to find $m = c$ <sup>d</sup> mod $n$ much more efficiently. Instead of computing $m = c$ <sup>d</sup> mod $n$, RSA-CRT computes $m$<sub>p</sub> = $c$<sup>d mod (p-1)</sup> mod $p$ and $m$<sub>q</sub> = $c$<sup>d mod (q-1)</sup> mod $q$. 

```python
def RSA_CRT():
	#set p and q and generate key n
	p,q = 10000139,10000141 
	
	#get public and private keys
	n,e,d = rsa.generate_keys(p,q)

	#set the message
	message_bytes = b'test!'
	#message_bytes = message.encode('utf-8')
	message_int = int.from_bytes(message_bytes,'big')
	#encrypt it 
	ciphertext = encrypt.rsa_encrypt(message_int,e,n)

	#decrypt it
	#now find RSA-CRT parts to reduce the complexity of finding the exponent c^d mod n:
	#(m^e)^d = m mod pq
	#Using Fermat's Little Theorem, a^(p-1) = 1 mod p and a^(q-1) = 1 mod q.
	#i.e. a^b = a^(b mod p-1)mod p, for prime p.
	#To recombine using CRT, m = mq + q(q^(-1)(mp-mq)) mod p
	d_p = d % (p-1)
	d_q = d % (q-1)
	q_inv = modular_inverse.modular_inverse(q,p)
	message_p = pow(ciphertext,d_p,p)
	message_q = pow(ciphertext,d_q,q)
	
	h = (q_inv * (message_p - message_q)) % p
	message = message_q + h * q
	if(message == message_int):
		print("Messages match")
	else:
		print("Messages do not match")
```

In practice, RSA-CRT is used to optimise signing and decryption with the private key using $s$ = $m$<sup>d</sup> mod $n$. The receiver of the message can then verify the signature using $m$ = $s$<sup>e</sup> mod $n$. In a Bellcore attack, if an attacker knows the correct signature and a faulty signature then they can determine a factor of n.

```python
def Bellcore_attack():

	#set p and q and generate key n
	p,q = 10000139,10000141 
	
	#get public and private keys
	n,e,d = rsa.generate_keys(p,q)

	#set the message
	message_bytes = b'test!'
	#message_bytes = message.encode('utf-8')
	message_int = int.from_bytes(message_bytes,'big')
	#encrypt it 
	c = encrypt.rsa_encrypt(message_int,e,n)

	#The Bellcore attack can be used against RSA, but requires more than one faulty ciphertext.
	#Only one is needed to attack RSA-CRT.
	#Assume an attacker knows the correct signature,s = m^d mod n, and the faulty one,s_fault, as well.
	#He can find a factor of n by finding gcd(s - s_fault,n)
	s = pow(message_int,d,n)
	
	#now find RSA-CRT parts to reduce the complexity of finding the exponent c^d mod n:
	#(m^e)^d = m mod pq
	#Using Fermat's Little Theorem, a^(p-1) = 1 mod p and a^(q-1) = 1 mod q.
	#i.e. a^b = a^(b mod p-1)mod p, for prime p.
	#To recombine using CRT, m = mq + q(q^(-1)(mp-mq)) mod p
	d_p = d % (p-1)
	d_q = d % (q-1)
	s_p = pow(message_int,d_p,p)
	s_q = (pow(message_int,d_q,q) + 1234) % q #Create a fault
	
	q_inv = modular_inverse.modular_inverse(q,p)
	h = (q_inv * (s_p - s_q)) % p
	s_fault = (s_q + h * q) % n
	
	guess = gu.standard_gcd(s - s_fault,n)
	print("Found factor:",guess)

```
(Project files coming soon.)
