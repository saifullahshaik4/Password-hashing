#include "thread_hash.h"
#include <crypt.h>        
#include <stddef.h>
#include <stdio.h>       
#include <unistd.h>       
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <search.h>

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER; 
static pthread_mutex_t result_count = PTHREAD_MUTEX_INITIALIZER; 
FILE *file_op = NULL;
static int cracked_pass = 0;
static int global_index = 0;
void print_help(void);
void * hash_pass(void * arg);
int read_lines(const char * fn, char *** lines); 
double get_time_in_seconds(struct timeval start, struct timeval end);

typedef struct {
    int thread_id;
    int dictionary_count;
    char ** dict_array;
    char ** hash_array;
    int algorithm_count[ALGORITHM_MAX];
    int verbose;
    int pass_count;
    
} thread_data_t;

int read_lines(const char * fn, char *** lines)
{
	FILE * f;
	int max = 10;
	char line_count[256];
	int counter = 0;

	f = fopen(fn, "r");
	if(!f)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	*lines = malloc(max * sizeof(char *)); 
	if(!(*lines))
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	while(fgets(line_count, sizeof(line_count), f))
	{
		if(counter >= max)
		{
			max *= 2;
			*lines = realloc(*lines, max * sizeof(char *));
			if(!(*lines))
			{
				perror("realloc");
				exit(EXIT_FAILURE);
			}
		}
		line_count[strcspn(line_count, "\n")] = 0;
		(*lines)[counter] = strdup(line_count);
		if(!(*lines)[counter])
		{
			perror("strdup");
			exit(EXIT_FAILURE);
		}
		++counter;
	}

	fclose(f);
	return counter;

}


void *hash_pass(void *arg) {
    struct timeval start, end;
    struct crypt_data crypt_stuff;
    thread_data_t *thread_data = (thread_data_t *)arg;
    int i;
    int func_index;
    double time_passed;

    gettimeofday(&start, NULL);
    memset(&crypt_stuff, 0, sizeof(crypt_stuff));

    while (1) {
	pthread_mutex_lock(&global_mutex);
	if(global_index >= thread_data->dictionary_count)
	{
		pthread_mutex_unlock(&global_mutex);
		break;
	}
	func_index = ++global_index;
	pthread_mutex_unlock(&global_mutex);

	for(int p = 0; p < thread_data->pass_count; ++p)
	{
		char * hashes = thread_data->hash_array[p];
		char * crypt = crypt_rn(thread_data->dict_array[func_index], hashes, &crypt_stuff, sizeof(crypt_stuff));

		if(crypt && strcmp(crypt, hashes) == 0)
		{
			if(file_op)
			{
				fprintf(file_op, "cracked %s %s \n", thread_data->dict_array[func_index], hashes);
			}
			else
			{
				printf("cracked %s %s\n", thread_data->dict_array[func_index], hashes);
			}
			++i;
			pthread_mutex_lock(&result_count);
			++cracked_pass;
			pthread_mutex_lock(&result_count);
			break;
		}		

		if(hashes[0] != '$')
			thread_data->algorithm_count[DES]++;
		else
		{
			switch(hashes[1])
			{
				case '3': 
					thread_data->algorithm_count[NT]++; 
					break;
				case '1':
					thread_data->algorithm_count[MD5]++; 
					break;
				case '5':
					thread_data->algorithm_count[SHA256]++; 
					break;
				case '6':
					thread_data->algorithm_count[SHA512]++; 
					break;
				case 'y':
					thread_data->algorithm_count[YESCRYPT]++; 
					break;
				case 'g':
					thread_data->algorithm_count[GOST_YESCRYPT]++; 
					break;
				case 'b':
					thread_data->algorithm_count[BCRYPT]++; 
					break;
				default:
					break;
			}
		}			
	}
    }
    gettimeofday(&end, NULL);
    time_passed = get_time_in_seconds(start, end);

    fprintf(stderr, "Thread %d: Time: %f, Cracked Passwords: %d\n", thread_data->thread_id, time_passed, i);
    for(int k = 0; k < ALGORITHM_MAX; ++i)
    {
	fprintf(stderr, "Thread %d: %s count: %d\n", thread_data->thread_id, algorithm_string[k], thread_data->algorithm_count[k]);
    }

    pthread_exit(NULL);
}


double get_time_in_seconds(struct timeval start, struct timeval end) 
{
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / MICROSECONDS_PER_SECOND;
}

void print_help(void) {
    fprintf(stderr, "Usage: ./thread_hash -i inputfile -o outputfile -d dictfile -t numthreads -v -h -n nicevalue\n");
    fprintf(stderr, "\t-i file\t\tinput file name (required)\n");
    fprintf(stderr, "\t-o file\t\toutput file name (default stdout)\n");
    fprintf(stderr, "\t-d file\t\tdictionary file name (required)\n");
    fprintf(stderr, "\t-t #\t\tnumber of threads to create (default 1)\n");
    fprintf(stderr, "\t-v\t\tenable verbose mode\n");
    fprintf(stderr, "\t-h\t\thelpful text\n");
    fprintf(stderr, "\t-n #\t\tset nice value for the process\n");
}



int main(int argc, char* argv[]) {
    int thread_counter = 1;
    int size;
    int count;
    char* filename_ip = NULL;
    char* filename_op = NULL;
    char* filename_d = NULL;
    char ** dict_array;
    char ** hash_array;
    int opt = 0;
    int verbose = 0;
    thread_data_t thread_data[24];
    pthread_t threads[24];

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
            case 'i':
                if (verbose) {
                    fprintf(stderr, "Input file: %s\n", optarg);
                }
                filename_ip = optarg;
                break;
            case 'o':
                if (verbose) {
                    fprintf(stderr, "Output file: %s\n", optarg);
                }
                filename_op = optarg;
                break;
            case 'd':
                if (verbose) {
                    fprintf(stderr, "Dictionary file: %s\n", optarg);
                }
                filename_d = optarg;
                break;
            case 't':
                thread_counter = atoi(optarg);
                if (thread_counter <= 0 || thread_counter > 24) {
                    printf("Invalid thread count %d\n", thread_counter);
                    exit(EXIT_FAILURE);
                }
                if (verbose) {
                    fprintf(stderr, "Thread count: %d\n", thread_counter);
                }
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_help();
		break;
            case 'n':
                if (verbose) {
                    fprintf(stderr, "Nice value: %s\n", optarg);
                }
		nice(NICE_VALUE);
                break;
            default:
                fprintf(stderr, "Usage: %s -i inputfile -o outputfile -d dictfile -t numthreads -v -h -n nicevalue\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    if(!filename_d || !filename_ip)
	print_help();

    size = read_lines(filename_d, &dict_array);
    count = read_lines(filename_ip, &hash_array);

    if(filename_op)
    {
	file_op = fopen(filename_op, "w");
	if(!file_op)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
	}
    }
    
    for(int k = 0; k < thread_counter; ++k)
    {
	thread_data[k].thread_id = k;
        thread_data[k].dict_array = dict_array;
        thread_data[k].dictionary_count = size;
        thread_data[k].hash_array = hash_array;
        thread_data[k].pass_count = count;
        thread_data[k].verbose = verbose;
        memset(thread_data[k].algorithm_count, 0, sizeof(thread_data[k].algorithm_count));
        pthread_create(&threads[k], NULL, hash_pass, (void *)&thread_data[k]);	
    }

    for (int i = 0; i < thread_counter; i++) {
        pthread_join(threads[i], NULL);
    }

    if (file_op) {
        fclose(file_op);
    }

    printf("Total Cracked Passwords: %d\n", cracked_pass);

    for (int i = 0; i < size; ++i) {
        free(dict_array[i]);
    }
    free(dict_array);

    for (int i = 0; i < count; ++i) {
        free(hash_array[i]);
    }
    free(hash_array);

    return 0;


}
