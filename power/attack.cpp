#include <iostream>
#include "attack.h"

using namespace std;

pid_t pid = 0;    // process ID (of either parent or child) from fork

int target_raw[2];   // unbuffered communication: attacker -> attack target
int attack_raw[2];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

// AES SubBytes
unsigned char SubBytes[256] = 
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

int HammingWeight[256] =
{
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

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

// interacts with the target *****.D
// send a message
// get the respective ciphertext and the power consumption
vector<int> interact(mpz_class &m, mpz_class &c, unsigned int &interaction_number)
{
    // interact with 61061.D
	gmp_fprintf(target_in, "%032ZX\n", m.get_mpz_t());
	fflush(target_in);
    
    // get power consumption and ciphertext
	int length;
	gmp_fscanf(target_out, "%d", &length);
    
    vector<int> current_power(length);
    for (int i = 0; i < length; i++)
        gmp_fscanf(target_out, ",%d", &current_power[i]);
    
    gmp_fscanf(target_out, "%ZX", c.get_mpz_t());
    interaction_number++;
    return current_power;
}

float mean(vector<int> trace)
{
    float sum = 0;
    
    for (int i = 0; i < trace.size(); i++)
        sum += trace[i];
    
    return (float) sum/trace.size();
}

// http://www.alglib.net/statistics/correlation.php
float corrcoef(vector<int> x, vector<int> y)
{
    // initialise: sum_xy is at the top, the other two - at the bottom
    float sum_xy = 0, sum_x = 0, sum_y = 0;
    
    // precompute for efficiency
    float mean_x = mean(x);
    float mean_y = mean(y);
    
    for (int i = 0; i < x.size(); i++)
        sum_xy += (x[i] - mean_x)*(y[i] - mean_y);
    
    for (int i = 0; i < x.size(); i++)
        sum_x += (x[i] - mean_x)*(x[i] - mean_x);    
    
    for (int i = 0; i < y.size(); i++)
        sum_y += (y[i] - mean_y)*(y[i] - mean_y);
    
    return (float) sum_xy/(sqrt(sum_x)*sqrt(sum_y));
}

void attack(char* argv2)
{
    // count the number of interactions with the target
    unsigned int interaction_number = 0;
    
    // declare variables for communication with the target
    mpz_class c, m;
    vector<int> current_power;
    vector<mpz_class> messages;
    int oracle_queries = 100;
    
    // produce random messages
    gmp_randclass randomness(gmp_randinit_default);
    
    // a 2D matrix of traces/powers
    vector< vector<int> > powers;
    
    // initial sample set and respective power traces
    for (int j = 0; j < oracle_queries; j++)
    {
        // compute a random message
        m = randomness.get_z_bits(128);
        messages.push_back(m);
        
        // find the power trace while encrypting it
        current_power = interact(m, c, interaction_number);
        powers.push_back(current_power);   
    }

    int min = powers[0].size();
    for (int j = 1; j < powers.size(); j++)
        if (powers[j].size() < min)
            min = powers[j].size();
    
    
    vector< vector<int> > powers_T(min, vector<int> (powers.size()));   //the 'transposed' vector
    for (int j = 0; j < min; j++)  
        for (int l = 0; l < powers.size(); l++)
	        powers_T[j][l] = powers[l][j];

    
    vector< vector<int> > target(messages.size(), vector<int> (256));
    vector< vector<int> > target_T(256, vector<int> (messages.size()));
    
    // recover 1 byte of the key at the time: 
    // 1 byte of the key corresponds to 1 byte of the message in AES
    for (int n = 0; n < 16; n++)
    {
        for (int j = 0; j < messages.size(); j++)
        {
            mpz_class temp = messages[j] >> (8*n);
            int current_byte = temp.get_si() & 0xff;
            // bitxor each byte of each message with each possible value for the key
            for (int key = 0; key < 256; key++)
                // Differential part of DPA: XOR -> SBox -> Hamming Weight
                target[j][key] = HammingWeight[SubBytes[current_byte ^ key]];
        }
        
        for (int j = 0; j < 256; j++)  
            for (int l = 0; l < target.size(); l++)
                target_T[j][l] = target[l][j];
        
        for (int j = 0; j < 256; j++)
        {
            if (powers_T[j].size() != target_T[j].size())
                continue;
            
            cout << "\n corrcoef = " << corrcoef(target_T[j], powers_T[j]);
        }
    }
    cout << "\nNumber of interactions with the target: " << interaction_number << "\n\n";

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
