#include <iostream>
#include "attack.h"

using namespace std;

pid_t pid = 0;    // process ID (of either parent or child) from fork

int target_raw[2];   // unbuffered communication: attacker -> attack target
int attack_raw[2];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

int interact(mpz_class &c, mpz_class &m, unsigned int &interaction_number);
void attack(char* argv2);
void attackR(char* argv2);
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

// Montgomery multiplication
mpz_class montgomery_multiplication(mpz_class x, mpz_class y, mp_limb_t omega, mpz_class N) 
{
    // work with a temp var instead of rop, so that the same variable can be passed as x and rop (similarly to native GMP functions)
    mpz_class r = 0;
    mp_limb_t u, y_i, x_0, r_0;
    
    // l_N - mpz_size(N)
    for (mp_size_t i = 0; i < mpz_size(N.get_mpz_t()); i++) 
    {
        // u <- (r_0 + y_i*x_0)*omega (mod b)
        y_i = mpz_getlimbn(y.get_mpz_t(), i); // i-th limb of y
        x_0 = mpz_getlimbn(x.get_mpz_t(), 0); // 0-th limb of x
        r_0 = mpz_getlimbn(r.get_mpz_t(), 0); // 0-th limb of r
        u = (r_0 + y_i * x_0) * omega;
        
        // r <- (r + y_i*x + u*N)/b
        r += y_i * x; // r <- r + y_i*x
        r += u * N;   // r <- r + u*N
        mpz_tdiv_q_2exp(r.get_mpz_t(), r.get_mpz_t(), mp_bits_per_limb);  // r <- r/b
    }
     
    return r;
}

// Computing omega
void montgomery_omega(mp_limb_t &omega, mpz_class N) 
{
    // omega <- 1 (mod b)
    omega = 1;
    
    // b is the 0th limb of N, 
    mp_limb_t b = mpz_getlimbn(N.get_mpz_t(), 0);
    
    for (mp_size_t i = 1; i <= mp_bits_per_limb; i++)
        // omega <- omega * omega * N (mod b)
        omega *= omega * b;
    
    // omega = -omega (mod b)
    omega = -omega;
}

// Computing rho^2
void montgomery_rho_sq(mpz_class &rho_sq, mpz_class N) 
{
    // rho_sq <- 1 (mod N)
    rho_sq = 1;
    
    // upto 2 * l_N * w
    for (mp_size_t i = 1; i < 2 * mpz_size(N.get_mpz_t()) * mp_bits_per_limb + 1; i++) 
    {
        // rho^2 <- rho^2 + rho^2
        rho_sq += rho_sq;
        
        // modular reduction instead of mpz_mod
        // if rho^2 > N, rho^2 <- rho^2 - N
        if (rho_sq > N)
            rho_sq -= N;
    }
}

// Convert a number into a montgomery number
// num should be < N
mpz_class montgomery_number(mpz_class num, mpz_class rho_sq, mp_limb_t omega, mpz_class N) 
{
    // r <- mont_num = num * rho (mod N)
    return montgomery_multiplication(num, rho_sq, omega, N) % N;
}

// Montgomery reduction
void montgomery_reduction(mpz_class &rop, mpz_class t, mp_limb_t omega, mpz_class N) 
{
    // r <- t
    mpz_class r = t;
    mpz_class b_times_N;
    mp_limb_t u, r_i;
    
    // l_N - mpz_size
    for (mp_size_t i = 0; i < mpz_size(N.get_mpz_t()); i++) 
    {
        r_i = mpz_getlimbn(r.get_mpz_t(),i);
 
        // u <- r_i*omega (mod b)
        u = r_i * omega;
        
        // r <- r + (u*N*(b^i))
        mpz_mul_2exp(b_times_N.get_mpz_t(), N.get_mpz_t(), mp_bits_per_limb * i);
        r += b_times_N*u;
    }

    // r <- r / b ^ (l_N)
    mpz_tdiv_q_2exp(r.get_mpz_t(), r.get_mpz_t(), mp_bits_per_limb * mpz_size(N.get_mpz_t()) );
    
    // if r > N, r <- r - N
    if(r > N)
        r -= N;
    
    mpz_swap(rop.get_mpz_t(), r.get_mpz_t()); // mpz_swap is O(1), while mpz_set is O(n) where n is the number of limbs
}

// Convert vector of bools to a number
mpz_class vec_to_num(const vector<bool> &d)
{
    mpz_class d_num = 0;
    for (bool bit : d)
        d_num = d_num * 2 + bit;
    return d_num;
}

// check whether the recovered key is the actual private key
bool verify(const mpz_class &e, const mpz_class &N, const mpz_class &sk, unsigned int &interaction_number,
            const mpz_class &c, mpz_class &m_prime)
{
    // m_prime holds the decrypted by the oracle message
    // of c_vrfy = 0b1010
    
    // decrypt ciphertext manually
    mpz_class m;
    mpz_powm(m.get_mpz_t(), c.get_mpz_t(), sk.get_mpz_t(), N.get_mpz_t());
      
    // check if the two messages are the same
    if (m == m_prime)
        return true;
    else
        return false;
}

// interacts with the target *****.D
// send a ciphertext
// get the decrypted message and the execution time
int interact(mpz_class &c, mpz_class &m, unsigned int &interaction_number)
{
    // interact with 61061.D
	gmp_fprintf(target_in, "%0256ZX\n", c.get_mpz_t());
	fflush(target_in);
    
    // get execution time
	int time;
	gmp_fscanf(target_out, "%d\n%ZX", &time, m.get_mpz_t());
    interaction_number++;
    return time;
}

// interacts with the target replica *****.R
// send a ciphertext, a modulus and a private key
// get the decrypted message and the execution time
int calibrate(mpz_class &c, mpz_class &N, mpz_class &d, mpz_class &m)
{
    // interact with 61061.R
	gmp_fprintf(target_in, "%0256ZX\n%0256ZX\n%0256ZX\n", c.get_mpz_t(), N.get_mpz_t(), d.get_mpz_t());
	fflush(target_in);
    
    // get execution time
	int time;
	gmp_fscanf(target_out, "%d\n%ZX", &time, m.get_mpz_t());
    return time;
}

// test function to obtain times for different key from
// the target replica
// used to compute the time needed for a single Montgomery
// multiplication which helps find the 
// number of bits + hamming weight
void attackR(char* argv2)
{
    // interact with 61061.conf
    // reading the input
	ifstream config (argv2, ifstream::in);
	mpz_class N, e;
	config >> hex >> N >> e;
    
    // declare variables for communication with the target replica
    mpz_class c = 0b00, m, d;
    int time, time1, time2, time3, time4, time5, time6, time7;
    vector<int> times;
    
    // try the target replica with different keys
    // investigate the results and the differences between them
    d = 0b1001;
    time1 = calibrate(c, N, d, m);
    cout << "Time for d = 1001: " << time1 << endl;
    times.push_back(time1); 
    d = 0b1010;
    time = calibrate(c, N, d, m);
    cout << "Time for d = 1010: " << time << endl;
    times.push_back(time);
    d = 0b1100;
    time = calibrate(c, N, d, m);
    cout << "Time for d = 1100: " << time << endl;
    times.push_back(time);
    d = 0b1000;
    time2 = calibrate(c, N, d, m);
    cout << "Time for d = 1000: " << time2 << endl;
    cout << "Difference between 1001 and 1000: " << time1 - time2 << endl;
    d = 0b100;
    time4 = calibrate(c, N, d, m);
    cout << "Time for d = 100: " << time4 << endl;
    cout << "Difference between 100 and 1001: " << time1 - time4 << endl;
    cout << "Difference between 100 and 1100: " << time - time4 << endl;
    cout << "Difference between 100 and 1000: " << time2 - time4 << endl;
    d = 0b1110;
    time3 = calibrate(c, N, d, m);
    cout << "Time for d = 1110: " << time3 << endl;
    cout << "Difference between 1110 and  1001: " << time3 - time1 << endl;
    d = 0b1;
    time5 = calibrate(c, N, d, m);
    cout << "Time for d = 1: " << time5 << endl;
    d = 0b10;
    time6 = calibrate(c, N, d, m);
    cout << "Time for d = 10: " << time6 << endl;
    d = 0b11;
    time7 = calibrate(c, N, d, m);
    cout << "Time for d = 11: " << time7 << endl;
    
    time = 0;
    for (int i = 0; i < 3; i++)
    {
        time += times[i];
    }
    cout << "Average time: " << time/3 << endl;
    
    
    
}


// function executing the actual attack on the target
// called from main
void attack(char* argv2)
{
    // count the number of interactions with the target
    unsigned int interaction_number = 0;
    
    // count the number of resamples
    unsigned int resamples = 0;
    
	// interact with 61061.conf
    // reading the input
	ifstream config (argv2, ifstream::in);
	mpz_class N, e;
	config >> hex >> N >> e;
    
    // initialise verification variables
    mpz_class c_vrfy = 0b1010, m_vrfy;
    interact(c_vrfy, m_vrfy, interaction_number); 
    // decrypt the ciphertext with the oracle
    
    // execution times for the initial sample set of ciphertexts
    vector<int> times;
    
    // declare variables for communication with the target
    mpz_class c = 0, m;
    int time_c = 0;
    
    // time it takes to do a single Montgomery multiplication
    // got from 61061.R
    int time_op = 3770, time_overhead = 2*time_op;
    
    // get execution time: time it takes the targer to decrypt 
    // a ciphertext with the private key we aim to recover
    int time_ex = interact(c, m, interaction_number);
    
    // No of (bits in key + hamming weight)
    int bits_num = (time_ex - time_overhead)/time_op;
    cout << "\nNo. of bits + Hamming weight: " << bits_num << "\n\n";
    // for each bit = 0 recovered, 1 will be subtracted,
    // for each bit = 1 recovered, 2 will be subtracted
    
    // vectors of ciphertexts
    vector<mpz_class> cs;
    vector<vector<mpz_class>> part_cs_mul_sq(bits_num), part_cs_sq(bits_num);
    
    // produce random ciphertexts
    gmp_randclass randomness (gmp_randinit_default);
    
    // Montgomery preprocessing
    mpz_class rho_sq;
    mp_limb_t omega;
    montgomery_omega(omega, N);
    montgomery_rho_sq(rho_sq, N);
    
    // d is the private key
    vector<bool> d;
    
    // initial number of samples
    int oracle_queries = 2000;
    
    // initial sample set and respective execution times
    for (int j = 0; j < oracle_queries; j++)
    {
        // compute a random ciphertext
        c = randomness.get_z_range(N);
        // find the time needed to decrypt it
        time_c = interact(c, m, interaction_number);
        
        // convert the ciphertext to a montgomery number
        // for the target simulation
        c = montgomery_number(c, rho_sq, omega, N);
        // save the current ciphertext
        cs.push_back(c);
        // and its execution time
        times.push_back(time_c);
        
        // compute the square
        c = montgomery_multiplication(c, c, omega, N);
        
        // vectors for partial exponentiations
        part_cs_mul_sq[0].push_back(c); // will be used when previous d_i = 1
        part_cs_sq[0].push_back(0);     // will be used when previous d_i = 0
    }
   
    ////////////////////////////////////////////////////////
    // ATTACK                                             //
    ////////////////////////////////////////////////////////
    
    // assume the first bit of d is 1
    d.push_back(1);
    bits_num -= 2;
    
    bool isKey = false, doResample = false;
    
    // bit and backtrack counter
    int bit_i = 0, backtracks = 0;
    vector<bool> isFlipped(bits_num, false);
    
    // mpz integer to hold the private key once recovered
    mpz_class sk;
    
    // until the key is fully recovered, attack
    while (!isKey)
    {
        // each time the program needs to backtrack too many times
        // additional 250 random ciphertexts are generated
        // and the key is attacked from the beginning
        if (doResample)
        {
            // add 250 more samples
            cout << "RESAMPLING\n";
            for (int j = 0; j < 250; j++)
            {
                // compute a random ciphertext
                c = randomness.get_z_range(N);
                // find the time needed to decrypt it
                time_c = interact(c, m, interaction_number);
                
                // convert the ciphertext to a montgomery number
                // for the target simulation
                c = montgomery_number(c, rho_sq, omega, N);
                // save the current ciphertext
                cs.push_back(c);
                // and its execution time
                times.push_back(time_c);
                
                // compute the square
                c = montgomery_multiplication(c, c, omega, N);
                
                // vectors for partial exponentiations
                part_cs_mul_sq[0].push_back(c); // will be used when previous d_i = 1
                part_cs_sq[0].push_back(0);     // will be used when previous d_i = 0
            }

            // clear all variables and start guessing the key again
            oracle_queries += 250; // update the counter
            fill(isFlipped.begin(), isFlipped.end(), false); // flipped bits vector
            bit_i = 0; // bit counter
            bits_num = (time_ex - time_overhead)/time_op - 2; // -2 as d starts with a 1
            d.clear(); // clear all guesses
            d.push_back(1); // push first bit 1
            doResample = false;
            backtracks = 0;
        }
        
        // keep track of the bit we are recovering
        bit_i++;
        
        /////////////////////////////////////////////////////////////
        // confidence measures - average calculations for hypotheses
        // case for bit is 1
        // time1 - no reduction; time1red - had reduction
        long long time1 = 0, time1red = 0;
        int time1_count = 0, time1red_count = 0; // counters
        
        // case for bit is 0
        // time0 - no reduction; time0red - had reduction
        long long time0 = 0, time0red = 0;
        int time0_count = 0, time0red_count = 0; // counters

        // for each sample ciphertext
        for (int j = 0; j < oracle_queries; j++)
        {
            // x is the current calculation, prev_x is the previous calculation
            mpz_class x, prev_x;
            
            // obtain the time it took to decrypt the current
            // ciphertext with the target
            int current_time = times[j];
            
            // get partial exponentiation based on previous bit
            if (d.back() == 0)
                prev_x = part_cs_sq[bit_i-1][j];
            else
                prev_x = part_cs_mul_sq[bit_i-1][j];
            
            
            //////////////////////////////////////////////////////
            // CASE WHERE
            // d_i = 0
            
            // SQUARE
            x = montgomery_multiplication(prev_x,prev_x,omega,N);
            
            // MODULAR REDUCTION
            if (x >= N)
            {
                x = x % N;
                time0red += current_time; // add the current time to the sum
                time0red_count++; // increment counter
            }
            else
            {
                time0 += current_time; // add the current time to the sum
                time0_count++; // increment counter
            }
            
            // insert or update the partial exponentiation for the case d_i = 0
            if(part_cs_sq[bit_i].size() <= j)
                part_cs_sq[bit_i].push_back(x);
            else
                part_cs_sq[bit_i][j] = x;
            
            
            //////////////////////////////////////////////////////
            // CASE WHERE
            // d_i = 1
            
            // MULTIPLY
            x = montgomery_multiplication(prev_x,cs[j],omega,N);
            
            //MODULAR REDUCTION
            if (x >= N)
                x = x % N;
            
            // SQUARE
            x = montgomery_multiplication(x,x,omega,N);
            
            //MODULAR REDUCTION
            if (x >= N)
            {
                x = x % N;
                time1red += current_time; // add the current time to the sum
                time1red_count++; // increment counter
            }
            else
            {
                time1 += current_time; // add the current time to the sum
                time1_count++; // increment counter
            }
            
            // insert or update the partial exponentiation for the case d_i = 1
            if(part_cs_mul_sq[bit_i].size() <= j)
                part_cs_mul_sq[bit_i].push_back(x);
            else
                part_cs_mul_sq[bit_i][j] = x;   
        }
        
        // ensure no division by 0 is done
        // and average the values for all cases
        if (time1_count != 0)
            time1 = time1/time1_count;
        
        if (time0_count != 0)
            time0 = time0/time0_count;
        
        if (time1red_count != 0)
            time1red = time1red/time1red_count;
        
        if (time0red_count != 0)
            time0red = time0red/time0red_count;
        
        // check if confidence measure is high enough
        // second check ensures there are still bits to be recovered
        if(abs(abs(time1-time1red) - abs(time0-time0red)) > 6 && bits_num > 0)
        {
            // check which bit should be predicted based on confidence measures
            // and update the number of bits left to recover (bits_num)
            if (abs(time1-time1red) > abs(time0-time0red))
            {
                // predict 1
                d.push_back(1);
                bits_num-=2;  
            }
            else
            {
                // predict 0
                d.push_back(0);
                bits_num--;
            }
            
            // error correction case for backtracking once only
            if(isFlipped[bit_i])
            {
                isFlipped[bit_i] = false;
                backtracks = 0;
            }
        }
        else // confidence is not strong enough, hence backtrack
        {
            bit_i--; // decrement bit count for each backtrack
            
            while(isFlipped[bit_i])
            {
                // the beginning of d has been reached, resample 
                // and start to attack again
                if(bit_i == 0)
                {
                    doResample = true;
                    break;
                }
                
                // adjust hamming weight + number of bits
                bits_num += d.back() + 1;
                // remove guess for the last bit
                d.pop_back();
                // decrement bit count for each backtrack
                bit_i--;
                // increment how much it has backtracked
                backtracks++;
            }
            
            // if it's backtracked too much, resample
            if (backtracks > 2)
                doResample = true;

            // if the beginning of the key has been reached, resample
            if(doResample)
                continue;
            
            // if the last bit is 1, set it to 0
            if (d.back())
            {
                d.pop_back();
                d.push_back(0);
                // adjust hamming weight + number of bits
                bits_num++;
            }
            else // if the last bit is 0, set it to 1
            {
                d.pop_back();
                d.push_back(1);
                // adjust hamming weight + number of bits
                bits_num--;
            }
            
            // keep track of the flipped bits
            isFlipped[bit_i] = true; 
        }
        
        // check if we have recovered the full private key
        if(bits_num == 0)
        {
            // convert the vector of bits to an mpz integer
            sk = vec_to_num(d);
            // check if it's the right private key
            isKey = verify(e, N, sk, interaction_number, c_vrfy, m_vrfy);
        }
    }
    
    cout << "\nd = ";
    for (int j = 0; j < d.size(); j++)
        cout << d[j];
    
    cout << "\nd = " << hex << uppercase << sk;
    
    cout << "\nInteractions: " << dec << interaction_number << "\n";
    
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
