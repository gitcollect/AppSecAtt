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


int interact(const mpz_class &l_prime, const mpz_class &c_prime)
{
    //cout << "In interact" << endl;
    // interact with 61061.D
	gmp_fprintf(target_in, "%ZX\n%0256ZX\n", l_prime.get_mpz_t(), c_prime.get_mpz_t());
    //cout << "Before flush" << endl;
	fflush(target_in);
    //cout << "After flush" << endl;
    
    //       code 0: decryption success 
    // error code 1: y >= B
    // error code 2: y < B (?)
    
    // Print error code
	int code;
	fscanf(target_out, "%X", &code);
	//cout << "Error code: " << code << "\n";
    return code;
}

void attack(char* argv2)
{
    unsigned int interaction_number = 0;
	// interact with 61061.conf
    // reading the input
	ifstream config (argv2, ifstream::in);
	mpz_class N, e, l_prime, c_prime;
	config >> hex >> N >> e >> l_prime >> c_prime;
    
    // print k = ceil(log 256 (N))
	//size_t sizeN = mpz_size(N.get_mpz_t());
    size_t k = mpz_sizeinbase(N.get_mpz_t(), 256);
	cout << "size of N in bytes: " << k << "\n";
    // print B = 2^(8*(k-1)) (mod N)
    // !!! assuming 2*B < N !!!
    mpz_class B;
    mpz_powm_ui(B.get_mpz_t(), mpz_class(2).get_mpz_t(), 8*(k - 1), N.get_mpz_t());
    //cout << "B = " << B << "\n";
    
    //////////////////////////////////////////////////////////////////////
    // ATTACK                                                           //
    //////////////////////////////////////////////////////////////////////
    
    //////////////////////////////////////////////////////////////////////
    // STEP 1.
    int code = -1, i = 1;
    mpz_class f_1;
    mpz_class f_1_exp;
    mpz_class c_1; // c_1 = f_1 * c' (mod N)

    while (code != 1) 
    {
        mpz_ui_pow_ui(f_1.get_mpz_t(), 2, i);
        mpz_powm(f_1_exp.get_mpz_t(), f_1.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
        c_1 = f_1 * c_prime % N;
        code = interact(l_prime, c_1);
        interaction_number++;
        i++;
    }
    
    //cout << "f_1 c [B/2, 2*B) = " << f_1 << "\n";
    
    
    //////////////////////////////////////////////////////////////////////
    // STEP 2.
    
    // f_2 = 2*B/f_1
	mpz_class f_2 = (N + B) / B * f_1 / 2;
    //cout << "f_2 = " << f_2 << "\n";
    mpz_class f_2_exp;
    mpz_class c_2;
    code = -1;
    
    while (true)
    {
        mpz_powm(f_2_exp.get_mpz_t(), f_2.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
        c_2 = f_2_exp * c_prime % N;        
        code = interact(l_prime, c_2);
        interaction_number++;
        
        if (code != 1)
            break;
        
        f_2 += f_1/2;
    }
    
    //cout << "f_2 = " << f_2 << "\n";
    
    //////////////////////////////////////////////////////////////////////
    // STEP 3.
    
    // m_min = ceil( n / f_2 )
    mpz_class m_min = (N + f_2 - 1)/f_2;
    //cout << "m_min = " << m_min << endl;
    // m_max = floor( (n + B) / f_2 )
    mpz_class m_max = (N + B)/f_2;
    //cout << "m_max = " << m_max << endl;
    
    mpz_class f_3, f_3_exp, c_3, f_tmp;
    mpz_class i_bound;
    
    while(m_min != m_max)
    {
        f_tmp = 2*B / (m_max - m_min);
        //cout << "f_tmp = " << f_tmp << "\n";
        
        i_bound = f_tmp * m_min / N;
        f_3 = (i_bound * N + m_min - 1) / m_min;
        
        mpz_powm(f_3_exp.get_mpz_t(), f_3.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
        c_3 = f_3_exp * c_prime % N;
        
        code = interact(l_prime, c_3);
        interaction_number++;
        
        if (code == 1)
            m_min = (i_bound * N + B + f_3 - 1) / f_3;
        else if (code == 2)
            m_max = (i_bound * N + B) / f_3;
    }
    
    mpz_class c_check;
    mpz_powm(c_check.get_mpz_t(), m_min.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
    
    if (c_check == c_prime)
        cout << "MOO WINS!!!" << endl;
    
    
    size_t sizeinbase = mpz_sizeinbase(m_min.get_mpz_t(), 256); 
    //holder for the byte array
    unsigned char buffer[128] = {0}, bufferL[128] = {0};
    
    // convert m_min from mpz_class to a byte array
    // have the behaviour of I2OSP
    mpz_export(buffer + 128 - sizeinbase, NULL, 1, 1, 0, 0, m_min.get_mpz_t());
    
    cout << "Buffer = ";
    for (int j = 0; j < 128; j++)
        printf("%02X", (unsigned int)buffer[j]);
    
    cout << endl;
    cout << endl;
    
    //////////////////////////////////////////////////////////////////////
    // EME-OAEP Decoding                                                //
    //////////////////////////////////////////////////////////////////////
    
    // 3. a.
    // convert l_prime to byte array
    sizeinbase = mpz_sizeinbase(l_prime.get_mpz_t(), 256);
    mpz_export(bufferL, NULL, 1, 1, 0, 0, l_prime.get_mpz_t());
    
    // digest for l_prime
    unsigned char digest[SHA_DIGEST_LENGTH];
    
    //size_t SHA_DIGEST_LENGTH = SHA_DIGEST_LENGTH;
    
    // hash
    SHA1(bufferL, sizeinbase, digest);
    
    cout << "lHash = ";
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        printf("%02X", (unsigned int)digest[j]);
    
    cout << endl;
    
    // 3. b.
    unsigned char Y = buffer[0];
    printf("Y = %02X", Y);
    cout << endl;
    
    cout << "maskedSeed = ";
    unsigned char maskedSeed[SHA_DIGEST_LENGTH];
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        maskedSeed[j] = buffer[j+1];
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        printf("%02X", (unsigned int)maskedSeed[j]);
    cout << endl;
    
    cout << "maskedDB = ";
    unsigned char maskedDB[k - SHA_DIGEST_LENGTH - 1];
    for (int j = 0; j < k - SHA_DIGEST_LENGTH - 1; j++)
        maskedDB[j] = buffer[j+SHA_DIGEST_LENGTH+1];
    for (int j = 0; j < k - SHA_DIGEST_LENGTH - 1; j++)
        printf("%02X", (unsigned int)maskedDB[j]);
    cout << endl;
    
    // 3. c.
    cout << "seedMask =   ";
    unsigned char seedMask[SHA_DIGEST_LENGTH];
    PKCS1_MGF1(seedMask, SHA_DIGEST_LENGTH, maskedDB, k - SHA_DIGEST_LENGTH - 1, EVP_sha1());
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        printf("%02X", seedMask[j]);
    cout << endl;
    
    // 3. d.
    cout << "seed = ";
    unsigned char seed[SHA_DIGEST_LENGTH];

    {
        int j = 0, l = 0, r = 0;
        
        for (; j < SHA_DIGEST_LENGTH; j++)
            if (maskedSeed[j] != 0)
                break;
        
        for (; l < SHA_DIGEST_LENGTH; l++)
            if (seedMask[l] != 0)
                break;
        
        /*    
        if (j > l)
            l = j;
        */
        for (; r < SHA_DIGEST_LENGTH && l < SHA_DIGEST_LENGTH&& j < SHA_DIGEST_LENGTH; r++, l++, j++)
            seed[r] = maskedSeed[j] ^ seedMask[l];

        for (r = 0; r < SHA_DIGEST_LENGTH; r++)
            printf("%02X", (unsigned int)seed[r]);
        cout << endl;
    }
    
    // 3. e.
    cout << "dbMask = ";
    unsigned char dbMask[k - SHA_DIGEST_LENGTH - 1];
    PKCS1_MGF1(dbMask, k - SHA_DIGEST_LENGTH - 1, seed, SHA_DIGEST_LENGTH, EVP_sha1());
    for (int j = 0; j < k - SHA_DIGEST_LENGTH - 1; j++)
        printf("%02X", (unsigned int)dbMask[j]);
    cout << endl;
    
    // 3. f.
    cout << "DB = ";
    unsigned char DB[k - SHA_DIGEST_LENGTH - 1];
    {
        int j = 0, l = 0, r = 0;
        
        for (; j < k - SHA_DIGEST_LENGTH - 1; j++)
            if (maskedDB[j] != 0)
                break;
        
        for (; l < k - SHA_DIGEST_LENGTH - 1; l++)
            if (dbMask[l] != 0)
                break;
        
       /*
        if (j > l)
            l = j;*/
        
        for (; j < k - SHA_DIGEST_LENGTH - 1 && l < k - SHA_DIGEST_LENGTH - 1 ; r++, l++, j++)      
            DB[r] = maskedDB[j] ^ dbMask[l];
        
        for (int j = r; j < k - SHA_DIGEST_LENGTH - 1; j++)
            DB[j] = 0;
        
        for (int j = 0; j < r; j++)
            printf("%02X", (unsigned int)DB[j]);
        cout << endl;
        cout << endl;    
    }
    
    // 3. g.
    //cout << "lHash_prime = ";
    cout << "     ";
    unsigned char lHash_prime[SHA_DIGEST_LENGTH];
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        lHash_prime[j] = DB[j];
    
    if (bufferL == lHash_prime)
        cout << "YEAH\n";
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        printf("%02X", DB[j]);
    
    int j = SHA_DIGEST_LENGTH;
    for (; j < k - SHA_DIGEST_LENGTH - 1; j++)
        if (DB[j] == 1)
            break;
        
    cout << endl << endl;
    
    unsigned char message[k - SHA_DIGEST_LENGTH - 2 - j];
    for (int l = j + 1, i = 0; l < k - SHA_DIGEST_LENGTH - 1 && i < k - SHA_DIGEST_LENGTH - 2 - j; l++, i++)
        message[i] = (unsigned int)DB[l];
        //printf("%02X", (unsigned int)DB[l]);
    
    for (int i = 0; i < k - SHA_DIGEST_LENGTH - 2 - j; i++)
        printf("%02X", (unsigned int)message[i]);
    cout << endl;
    
    cout << "INTERACTIONS = " << interaction_number << endl;
    unsigned char c_check2[128];
    
    unsigned char e_check[128];
    unsigned char n_check[128];
    size_t size_e = mpz_sizeinbase(e.get_mpz_t(), 256);
    size_t size_n = mpz_sizeinbase(N.get_mpz_t(), 256);
    mpz_export(e_check, NULL, 1, 1, 0, 0, e.get_mpz_t());
    mpz_export(n_check, NULL, 1, 1, 0, 0, N.get_mpz_t());
    
    RSA *rsa;
    rsa = RSA_new();
    rsa->e = BN_bin2bn(e_check, 128, rsa->e);
    cout << e << endl;
    cout << &rsa->e << endl;
    rsa->n = BN_bin2bn(n_check, 128, rsa->n);
    //RSA_generate_key_ex(e_rsa, 1024, &e_convert, NULL);
    
    RSA_public_encrypt(k - SHA_DIGEST_LENGTH - 2 - j, message, c_check2, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    
    cout << endl << "c_check  = " << c_prime;
    cout << endl << mpz_sizeinbase(c_prime.get_mpz_t(), 256);
    
    cout << endl << "c_check2 = ";
    for (int i = 0; i < 128; i++)
        cout << (unsigned int) c_check2[i];
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
