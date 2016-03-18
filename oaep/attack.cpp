#include <iostream>
#include "attack.h"

using namespace std;

pid_t pid = 0;    // process ID (of either parent or child) from fork

int target_raw[2];   // unbuffered communication: attacker -> attack target
int attack_raw[2];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void attack(char* argv2);
void cleanup(int s);

int main(int argc, char* argv[])
{

	// Ensure we clean-up correctly if Control-C (or similar) is signalled.
  	signal(SIGINT, &cleanup);

	// Create pipes to/from attack target; if it fails the reason is stored
	// in errno, but we'll just abort.
	if(pipe(target_raw) == -1)
		abort();
	  
	if(pipe(attack_raw) == -1)
		abort();

	switch(pid = fork()) 
	{ 
	    case -1: 
			// The fork failed; reason is stored in errno, but we'll just abort.
			abort();

	    case +0: 
	    {
			// (Re)connect standard input and output to pipes.
			close(STDOUT_FILENO);
			if(dup2(attack_raw[1], STDOUT_FILENO) == -1)
				abort();

			close(STDIN_FILENO);
			if(dup2(target_raw[0], STDIN_FILENO) == -1)
				abort();

			// Produce a sub-process representing the attack target.
			execl(argv[1], argv[0], NULL);

			// Break and clean-up once finished.
			break;
	    }

	    default:
	    {
			// Construct handles to attack target standard input and output.
			if((target_out = fdopen(attack_raw[0], "r")) == NULL) 
				abort();

			if((target_in = fdopen(target_raw[1], "w")) == NULL)
				abort();

			// Execute a function representing the attacker.
			attack(argv[2]);

			// Break and clean-up once finished.
			break;
	    }
	}

	// Clean up any resources we've hung on to.
	cleanup(SIGINT);

	return 0;
}

// interact with the target by inputting a label and a ciphertext
// obtain and return an error code
int interact(const mpz_class &l_prime, const mpz_class &c_prime)
{
    // interact with 61061.D
	gmp_fprintf(target_in, "%ZX\n%0256ZX\n", l_prime.get_mpz_t(), c_prime.get_mpz_t());
	fflush(target_in);

    //       code 0: decryption success 
    // error code 1: y >= B
    // error code 2: y < B
    
    // return error code
	int code;
	fscanf(target_out, "%X", &code);
    
    return code;
}

// attack the target to recover the message
// unmask and unpad the result from the attack to obtain the "pure" message
void attack(char* argv2)
{
    // count the number of interactions with the target
    unsigned int interaction_number = 0;
    
	// interact with 61061.conf
    // reading the input
	ifstream config (argv2, ifstream::in);
	mpz_class N, e, l_prime, c_prime;
	config >> hex >> N >> e >> l_prime >> c_prime;
    
    // k = ceil(log 256 (N))
    size_t k = mpz_sizeinbase(N.get_mpz_t(), 256);
	
    // B = 2^(8*(k-1)) (mod N)
    // !!! assuming 2*B < N !!!
    mpz_class B;
    mpz_powm_ui(B.get_mpz_t(), mpz_class(2).get_mpz_t(), 8*(k - 1), N.get_mpz_t());
    
    // abort if condition does not hold
    if (2*B >= N)
    {
        cout << "Error: 2*B >= N\n";
        return;
    }        
 
    //////////////////////////////////////////////////////////////////////
    // ATTACK                                                           //
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // STEP 1.
    int code = -1, i = 1;
    mpz_class f_1;
    mpz_class f_1_exp;
    mpz_class c_1; // c_1 = f_1 * c' (mod N)

    // increase f_1 until error code 1 is received
    while (code != 1) 
    {
        mpz_ui_pow_ui(f_1.get_mpz_t(), 2, i); // f_1 = 2^i where i is the iteration
        mpz_powm(f_1_exp.get_mpz_t(), f_1.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t()); // compute (f_1)^e (mod N)
        c_1 = f_1_exp * c_prime % N; // c_1 = (f_1)^e * c' (mod N)
        code = interact(l_prime, c_1); // send c_1 to the oracle and get the error code
        interaction_number++; // increment number of interactions
        i++; // increment exponent for updating f_1 at the next round
    }
    
    // => f_1/2 * m c [B/2, B) for a known multiple f_1/2
    //////////////////////////////////////////////////////////////////////
    // STEP 2.
	mpz_class f_2 = (N + B) / B * f_1 / 2; // initialise f_2 using f_1 from the previous step
    // f_2 = floor((N+B)/B)*f_1/2
    mpz_class f_2_exp;
    mpz_class c_2;
    code = -1;
    
    while(true)
    {
        mpz_powm(f_2_exp.get_mpz_t(), f_2.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t()); // compute (f_2)^e (mod N)
        c_2 = f_2_exp * c_prime % N; // c_2 = (f_2)^e * c' (mod N)      
        code = interact(l_prime, c_2); // send c_2 to the oracle and get error code
        interaction_number++; // increment number of interactions
        
        // break out of the loop and proceed to step 3.
        // must occur at or before f_2 = ceil(2N/B) * f_1/2
        if (code != 1)
            break;
        
        f_2 += f_1/2; // update f_2 = f_2 + f_1/2
    }    
    //////////////////////////////////////////////////////////////////////
    // STEP 3.
    
    // m_min = ceil(n / f_2)
    mpz_class m_min = (N + f_2 - 1)/f_2;
    // m_max = floor((n + B) / f_2)
    mpz_class m_max = (N + B)/f_2;
    
    // f_2 * (m_max - m_min) ~ B
    
    mpz_class f_3, f_3_exp, c_3, f_tmp;
    mpz_class i_bound;
    
    while(m_min != m_max)
    {
        f_tmp = 2*B / (m_max - m_min); // f_tmp = floor (2B/ (m_max - m_min))       
        i_bound = f_tmp * m_min / N; // i = floor(f_tmp*m_min/N)
        f_3 = (i_bound * N + m_min - 1) / m_min; // f_3 = ceil(i*N/m_min)
        
        mpz_powm(f_3_exp.get_mpz_t(), f_3.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t()); // compute (f_3)^e (mod N)
        c_3 = f_3_exp * c_prime % N; // c_3 = (f_3)^e * c' (mod N)
        
        code = interact(l_prime, c_3); // send c_3 to the oracle and get error code
        interaction_number++; // increment number of interactions
        
        if (code == 1)
            m_min = (i_bound * N + B + f_3 - 1) / f_3; // m_min = ceil((i*N + B)/f_3)
        else if (code == 2)
            m_max = (i_bound * N + B) / f_3; // m_max = floor((i*N + B)/f_3)
    }
    
    mpz_class c_check;
    mpz_powm(c_check.get_mpz_t(), m_min.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
    
    if (c_check == c_prime)
        cout << "OAEP message is recovered successfully!\n\n";
    
    // get the number of bytes of the message
    size_t sizeinbase = mpz_sizeinbase(m_min.get_mpz_t(), 256);
    
    //holder for the byte array
    unsigned char buffer[128] = {0}, bufferL[128] = {0};
    
    // convert m_min from mpz_class to a byte array
    // have the behaviour of I2OSP
    mpz_export(buffer + 128 - sizeinbase, NULL, 1, 1, 0, 0, m_min.get_mpz_t());
    
    cout << "OAEP message:\n";
    for (int j = 0; j < 128; j++)
        printf("%02X", (unsigned int)buffer[j]);
    
    cout << "\n\n";
    
    //////////////////////////////////////////////////////////////////////
    // EME-OAEP Decoding                                                //
    //////////////////////////////////////////////////////////////////////
    
    // 3. a.
    // compute lHash of size hLen = SHA_DIGEST_LENGTH: lHash = Hash(L)
    // convert l_prime to byte array
    sizeinbase = mpz_sizeinbase(l_prime.get_mpz_t(), 256);
    mpz_export(bufferL, NULL, 1, 1, 0, 0, l_prime.get_mpz_t());
    
    // digest for l_prime
    unsigned char lHash[SHA_DIGEST_LENGTH];
 
    // hash the label
    SHA1(bufferL, sizeinbase, lHash);
    
    // 3. b.
    // separate the encoded message: EM = Y || maskedSeed || maskedDB
    unsigned char Y = buffer[0];
    
    // maskedSeed is of length hLen = SHA_DIGEST_LENGTH
    unsigned char maskedSeed[SHA_DIGEST_LENGTH];
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        maskedSeed[j] = buffer[j+1];
    
    // maskedDB is of length k - hLen - 1
    unsigned char maskedDB[k - SHA_DIGEST_LENGTH - 1];
    for (int j = 0; j < k - SHA_DIGEST_LENGTH - 1; j++)
        maskedDB[j] = buffer[j+SHA_DIGEST_LENGTH+1];
    
    // 3. c.
    // seedMask = MGF(maskedDB, hLen)
    unsigned char seedMask[SHA_DIGEST_LENGTH];
    PKCS1_MGF1(seedMask, SHA_DIGEST_LENGTH, maskedDB, k - SHA_DIGEST_LENGTH - 1, EVP_sha1());
    
    // 3. d.
    // seed = maskedSeed xor seedMask
    unsigned char seed[SHA_DIGEST_LENGTH];

    {
        int j = 0, l = 0, r = 0;
        
        for (; j < SHA_DIGEST_LENGTH; j++)
            if (maskedSeed[j] != 0)
                break;
        
        for (; l < SHA_DIGEST_LENGTH; l++)
            if (seedMask[l] != 0)
                break;
        
        for (; r < SHA_DIGEST_LENGTH && l < SHA_DIGEST_LENGTH&& j < SHA_DIGEST_LENGTH; r++, l++, j++)
            seed[r] = maskedSeed[j] ^ seedMask[l];
    }
    
    // 3. e.
    // dbMask = MGF(seed, k - hLen - 1)
    unsigned char dbMask[k - SHA_DIGEST_LENGTH - 1];
    PKCS1_MGF1(dbMask, k - SHA_DIGEST_LENGTH - 1, seed, SHA_DIGEST_LENGTH, EVP_sha1());
    
    // 3. f.
    // DB = maskedDB xor dbMask
    unsigned char DB[k - SHA_DIGEST_LENGTH - 1];
    {
        int j = 0, l = 0, r = 0;
        
        for (; j < k - SHA_DIGEST_LENGTH - 1; j++)
            if (maskedDB[j] != 0)
                break;
        
        for (; l < k - SHA_DIGEST_LENGTH - 1; l++)
            if (dbMask[l] != 0)
                break;
        
        for (; j < k - SHA_DIGEST_LENGTH - 1 && l < k - SHA_DIGEST_LENGTH - 1 ; r++, l++, j++)      
            DB[r] = maskedDB[j] ^ dbMask[l];
        
        for (int j = r; j < k - SHA_DIGEST_LENGTH - 1; j++)
            DB[j] = 0;  
    }
    
    // 3. g.
    // separate DB = lHash' || PS || 0x01 || M
    // lHash' of length hLen = SHA_DIGEST_LENGTH
    // PS - octets with 0x00
    // M - the message
    unsigned char lHash_prime[SHA_DIGEST_LENGTH];
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        lHash_prime[j] = DB[j];
    
    // iterate through 0-s until 1 is reached
    int j = SHA_DIGEST_LENGTH;
    for (; j < k - SHA_DIGEST_LENGTH - 1; j++)
        if (DB[j] == 1)
            break;
    
    // obtain the message
    unsigned char message[k - SHA_DIGEST_LENGTH - 2 - j];
    for (int l = j + 1, i = 0; l < k - SHA_DIGEST_LENGTH - 1 && i < k - SHA_DIGEST_LENGTH - 2 - j; l++, i++)
        message[i] = (unsigned int)DB[l];
    
    // print the recovered message
    cout << "Recovered message:\n";
    for (int i = 0; i < k - SHA_DIGEST_LENGTH - 2 - j; i++)
        printf("%02X", (unsigned int)message[i]);
    cout << "\n\n";
    
    cout << "Number of interactions with the target: " << interaction_number << "\n\n";

}


void cleanup(int s) 
{
	// Close the   buffered communication handles.
	fclose(target_in);
	fclose(target_out);

	// Close the unbuffered communication handles.
	close(target_raw[0]); 
	close(target_raw[1]); 
	close(attack_raw[0]); 
	close(attack_raw[1]); 

	// Forcibly terminate the attack target process.
	if( pid > 0 )
		kill(pid, SIGKILL);

	// Forcibly terminate the attacker process.
	exit(1); 
}
