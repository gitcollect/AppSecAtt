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


void attack(char* argv2)
{
    // count the number of interactions with the target
    unsigned int interaction_number = 0;
    
    // declare variables for communication with the target
    mpz_class c, m;
    vector<int> current_power;
    int oracle_queries = 1000;
    mpz_class N = 1;
    N = N<<8*16;
    
    // produce random messages
    gmp_randclass randomness (gmp_randinit_default);
    
    vector<vector<int>> powers;
    
    // initial sample set and respective power traces
    for (int j = 0; j < oracle_queries; j++)
    {
        // compute a random message
        m = randomness.get_z_bits(128);
        cout << hex << m << endl;
        // find the power trace while encrypting it
        current_power = interact(m, c, interaction_number);
        powers.push_back(current_power);   
    }

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
