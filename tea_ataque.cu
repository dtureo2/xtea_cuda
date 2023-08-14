/*
	Ultima modificación: 13.10.2010
	tea_K: tiene la clave que se va a ocupar. UNA SOLA. se puede entregar por consola
	Plaintext son creados de forma ordenada.

	Mide tiempos

	Compilar con 'nvcc -o cuda tea_ataque.cu'
	Alternativa 	nvcc -o gpu_ataque -Xptxas "-v" -maxrregcount=10 tea_ataque.cu
								10 = desired maximum registers / kernel
	GNUPLOT:		
		gnuplot: plot 'times.tea' with points; set term png; set output 'times.png'; replot; set term x11
		f(x)=a*x+b; fit f(x) 'times.tea' via a,b
		plot 'times.tea' with points, f(x) ---
		plot 'times.tea' with points, f(x)=a*x+b; fit f(x) 'times.tea' via a,b
		gnuplot> plot 'times.tea' with points, f(x)
		gnuplot> set xlabel 'tiempos de CPU'
		gnuplot> set ylabel 'Rondas TEA'
		gnuplot> set title 'Fuerza Bruta sobre TEA'
		gnuplot> plot 'times.tea' title 'test'
		gnuplot> set term png; set output 'tiempos.png'; replot
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <cuda/cuda.h>
#include <cuda_runtime.h>

typedef unsigned char uchar;
typedef unsigned long ulong;
typedef unsigned int uint;
/* Execution parameters */
#define THREADS_PER_THREADBLOCK 64 //original: 128
#define BLOCKBUFFER_SIZE ( 4096 * THREADS_PER_THREADBLOCK) // 256 = 2^8 
//#define DATASIZE (128*512*8 / 2048) // original:8388608 =  2^23
#define DATASIZE 1024 //DATASIZE tiene que ser siempre mayor a THREADS_PER_THREADBLOCK
#define TEA_DELTA 0x9E3779B9
#define NUMPT 0x00000001
//Para valores mayores seria mejor ocupar una estructura

/* Data structures */
typedef struct {
    ulong k0, k1, k2,k3;
} TEA_KEY;

typedef struct{
    ulong v0, v1;
} TEA_BLOCK;

#define tea_K "tea_k.txt"
#define tea_plain "plain.tea"
#define tea_CP "teacu.xt"
#define tea_times "tiempoCuda.dat"

//ulong key2[2^36][4]; // Se podria usar mas adelante
ulong pt[NUMPT][2];
ulong cipher[NUMPT][2];
void test_cuda(void);
void mundzuk(int); // es el ataque de fuerza bruta
void plaintexts(void); // crea los textos planos
void leer_plaintexts(void); // lee los textos en claro desde un archivo llamado 'plain.tea'

FILE *teaplain, *teakey, *teacipher, *infile, *times;

#define TEA_ROUND(block,key,sum) \
{ \
    (block).v0 += ( ( (block).v1<<4) + (key).k0 ) ^ ( (block).v1 + sum) ^ ( ( (block).v1>>5) + (key).k1 ); \
    (block).v1 += ( ( (block).v0<<4) + (key).k2 ) ^ ( (block).v0 + sum) ^ ( ( (block).v0>>5) + (key).k3 ); \
}

#define TEA_ROUND2(block,key,sum) \
{ \
	(block).v1 -= ( ( (block).v0<<4) + (key).k2 ) ^ ( (block).v0 + sum) ^ ( ( (block).v0>>5) + (key).k3 ); \
	(block).v0 -= ( ( (block).v1<<4) + (key).k0 ) ^ ( (block).v1 + sum) ^ ( ( (block).v1>>5) + (key).k1 ); \
}

/*  GPU*/

__global__ void cuda_encrypt (TEA_BLOCK *v, TEA_KEY key){
    TEA_BLOCK tmp_v;
    int idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __syncthreads();
    tmp_v = v[idx];
    TEA_ROUND(tmp_v, key, TEA_DELTA*1); TEA_ROUND(tmp_v, key, TEA_DELTA*2);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*3); TEA_ROUND(tmp_v, key, TEA_DELTA*4);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*5); TEA_ROUND(tmp_v, key, TEA_DELTA*6);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*7); TEA_ROUND(tmp_v, key, TEA_DELTA*8);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*9); TEA_ROUND(tmp_v, key, TEA_DELTA*10);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*11); TEA_ROUND(tmp_v, key, TEA_DELTA*12);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*13); TEA_ROUND(tmp_v, key, TEA_DELTA*14);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*15); TEA_ROUND(tmp_v, key, TEA_DELTA*16);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*17); TEA_ROUND(tmp_v, key, TEA_DELTA*18);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*19); TEA_ROUND(tmp_v, key, TEA_DELTA*20);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*21); TEA_ROUND(tmp_v, key, TEA_DELTA*22);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*23); TEA_ROUND(tmp_v, key, TEA_DELTA*24);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*25); TEA_ROUND(tmp_v, key, TEA_DELTA*26);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*27); TEA_ROUND(tmp_v, key, TEA_DELTA*28);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*29); TEA_ROUND(tmp_v, key, TEA_DELTA*30);__syncthreads();
    TEA_ROUND(tmp_v, key, TEA_DELTA*31); TEA_ROUND(tmp_v, key, TEA_DELTA*32);
    v[idx] = tmp_v;
}

__global__ void cuda_decrypt (TEA_BLOCK *v, TEA_KEY key){
    TEA_BLOCK tmp_v;
    int idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __syncthreads();
    tmp_v = v[idx];
    TEA_ROUND2(tmp_v, key, TEA_DELTA*32); TEA_ROUND2(tmp_v, key, TEA_DELTA*31);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*30); TEA_ROUND2(tmp_v, key, TEA_DELTA*29);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*28); TEA_ROUND2(tmp_v, key, TEA_DELTA*27);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*26); TEA_ROUND2(tmp_v, key, TEA_DELTA*25);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*24); TEA_ROUND2(tmp_v, key, TEA_DELTA*23);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*22); TEA_ROUND2(tmp_v, key, TEA_DELTA*21);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*20); TEA_ROUND2(tmp_v, key, TEA_DELTA*19);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*18); TEA_ROUND2(tmp_v, key, TEA_DELTA*17);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*16); TEA_ROUND2(tmp_v, key, TEA_DELTA*15);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*14); TEA_ROUND2(tmp_v, key, TEA_DELTA*13);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*12); TEA_ROUND2(tmp_v, key, TEA_DELTA*11);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*10); TEA_ROUND2(tmp_v, key, TEA_DELTA*9);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*8); TEA_ROUND2(tmp_v, key, TEA_DELTA*7);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*6); TEA_ROUND2(tmp_v, key, TEA_DELTA*5);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*4); TEA_ROUND2(tmp_v, key, TEA_DELTA*3);
    TEA_ROUND2(tmp_v, key, TEA_DELTA*2); TEA_ROUND2(tmp_v, key, TEA_DELTA*1);
    v[idx] = tmp_v;
}

/* CPU*/

/*	Se encripta la data en mensage y se devuelve en output. len = DATASIZE*sizeof(TEA_BLOCK)
	op == 0 encripta, sino desencripta
	tea_crypt((uchar*)host_databuffer, DATASIZE*sizeof(TEA_BLOCK), (uchar*)host_databuffer, keya, 0))
*/ 
int tea_crypt(uchar* mensage, size_t len, uchar* output, TEA_KEY key, int op){
    void* gpu_databuffer;
    cudaEvent_t evt;
    size_t transfer_size, numBufferBlocks, numThreadBlocks;
    cudaError_t ret;

    /* Igual a DATASIZE que se van a encriptar/desencriptar */
    numBufferBlocks = len / sizeof(TEA_BLOCK);
	//printf("\n  number of Buffer Blocks: %d  ", numBufferBlocks);
    if (numBufferBlocks <= 0)
        return 0;
    /* We request page-locked memory from the CUDA api. Beware! */
    cudaMalloc(&gpu_databuffer, BLOCKBUFFER_SIZE * sizeof(TEA_BLOCK));
    while (numBufferBlocks > 0){
		//Nos aseguramos        
		transfer_size = numBufferBlocks > BLOCKBUFFER_SIZE ? BLOCKBUFFER_SIZE : numBufferBlocks;
		//transfer_size =  numBufferBlocks; // no nos aseguramos que lo tranferido sea igual a lo que hay en el buffer
        cudaMemcpy(gpu_databuffer, mensage, transfer_size*sizeof(TEA_BLOCK), cudaMemcpyHostToDevice);

        cudaEventCreate(&evt);
        numThreadBlocks = transfer_size / THREADS_PER_THREADBLOCK;// DATASIZE / THREAD....
		if(op == 0){
	        cuda_encrypt<<<numThreadBlocks, THREADS_PER_THREADBLOCK>>>((TEA_BLOCK *)gpu_databuffer, key);
		}else{
			cuda_decrypt<<<numThreadBlocks, THREADS_PER_THREADBLOCK>>>((TEA_BLOCK *)gpu_databuffer, key);
		}
        // usleeping() while the kernel is running saves CPU cycles but may decrease performance
        if (cudaEventRecord(evt, NULL) == cudaSuccess)
            while (cudaEventQuery(evt) == cudaErrorNotReady) { usleep(1000); }
        cudaEventDestroy(evt);
        ret = cudaGetLastError();
        if (ret != cudaSuccess || cudaThreadSynchronize() != cudaSuccess){
            printf("Kernel failed to run. CUDA threw error message '%s'\n", cudaGetErrorString(ret));
            cudaFree(gpu_databuffer);
            return 0;
        }
        cudaMemcpy(output, gpu_databuffer, transfer_size * sizeof(TEA_BLOCK), cudaMemcpyDeviceToHost);
        mensage += transfer_size * sizeof(TEA_BLOCK);
        output += transfer_size * sizeof(TEA_BLOCK);
        numBufferBlocks -= transfer_size;
    }
    cudaFree(gpu_databuffer);
    
    return 1;
}


int main(int argc, char **argv){
	cudaError_t ret;
    int i, j= 0;
    TEA_KEY keya;
    TEA_BLOCK* host_databuffer;
	ulong  key[4]; //Variables auxiliares 
	volatile double t1 = 0, t2;

	plaintexts(); // generacion de los textos planos. NUMPT contiene la cantidad que se van a generar
	//leer_plaintexts(); //lectura de los textos planos de un archivo
//	exit (2);
	teakey = fopen (tea_K, "r");
	if (! teakey) {
		perror ("Error opening " tea_K);
		exit (2);
	}
	while( !feof(teakey) ){
		fscanf (teakey, "%08lX %08lX %08lX %08lX", &(key[0]), &(key[1]), &(key[2]), &(key[3]) );
	}
	printf("KEY: %08lX %08lX %08lX %08lX \n", key[0], key[1], key[2], key[3] );

	mundzuk(NUMPT);
	printf("\n FIN PROGRAMA\n");
	exit(2);

	test_cuda(); // Indica si hay errores con la GPU
	// host_databuffer contiene a v0, v1
    ret = cudaMallocHost((void**)(&host_databuffer), DATASIZE * sizeof(TEA_BLOCK));
	if (ret != cudaSuccess){
        printf("Failed to allocate page-locked buffer.\n");
        return EXIT_FAILURE;
    }
    
	teacipher =  fopen(tea_CP, "w");
	if (! teacipher) {
		perror ("Error opening " tea_CP);
		exit (2);
	}
	t1 = clock();
	// SOLO ENCRIPTA.   Se van a cifrar NUMPT cantidad de mensajes
    for (j = 0; j < NUMPT; j++){
	    //printf("Run %i... ", j);
		keya.k0 = key[0];
	    keya.k1 = key[1];
	    keya.k2 = key[2];
	    keya.k3 = key[3];
		printf("pt: %08lX %08lX \n", pt[j][0], pt[j][1]);

		//Buscar que x q se repite 2^23 veces
        for (i = 0; i < DATASIZE; i++){
			host_databuffer[i].v0 = pt[j][0];
            host_databuffer[i].v1 = pt[j][1];
        }
        
		t2 = clock();
        if (!tea_crypt((uchar*)host_databuffer, DATASIZE*sizeof(TEA_BLOCK), (uchar*)host_databuffer, keya, 1))
        {
            printf("ERROR en teancrypt()\n");
            break;
        }
		t2 = (clock()-t2)/CLOCKS_PER_SEC;
		fprintf(teacipher,"%08lX %08lX\n", host_databuffer[j].v0, host_databuffer[j].v1 );
		printf("cipher: %08lX %08lX \n", host_databuffer[j].v0, host_databuffer[j].v1 );

    }
	t1 = (clock()-t1)/CLOCKS_PER_SEC;
 	printf(" \nt1: %.15f \t t2: %.15f \n", t1, t2);
	fclose(teacipher);
    cudaFreeHost(host_databuffer);

	times = fopen(tea_times,"a");
	if (! times) {
		perror ("Error creating file " tea_times);
		exit (2);
	}
	fprintf(times,"%.3f\t%d\t%d\t%d\n", t1, THREADS_PER_THREADBLOCK, BLOCKBUFFER_SIZE, DATASIZE);
	fclose(times);
	// Hasta aca mido tiempos!

//*/
//	mundzuk(NUMPT);
	printf("\n FIN PROGRAMA\n");
    return EXIT_SUCCESS;
}


//EL ataque de fuerza bruta
void mundzuk(int aux){ 
	cudaError_t ret;
	TEA_KEY keya;
    TEA_BLOCK* host_cipher, *cipher_aux;
	int count, j, i;
	ulong x;
	volatile double t1;

	keya.k0 = 0x00000000;
	keya.k1 = 0x00000000;
	keya.k2 = 0x00000000;
	infile = fopen (tea_CP, "r");
	if (! infile) {
		perror ("Error opening " tea_CP);
		exit (2);
	}
	count = 0;
	printf("Cifrados...");
	while( !feof(infile) ){
		if (count == NUMPT) break;
		fscanf (infile, "%08lX %08lX", &(cipher[count][0]), &(cipher[count][1]));
		printf("\n %08lX %08lX", cipher[count][0], cipher[count][1]);
		count++;
	}
	fclose (infile);
//	count--;
//	test_cuda();
	ret = cudaMallocHost((void**)(&host_cipher), DATASIZE * sizeof(TEA_BLOCK));
	if (ret != cudaSuccess){
        printf("Failed to allocate page-locked buffer.\n");
        return ;
	}
	ret = cudaMallocHost((void**)(&cipher_aux), DATASIZE * sizeof(TEA_BLOCK));
	if (ret != cudaSuccess){ // se ocupara como respaldo del cifrado que se quiere quebrar!
        printf("Failed to allocate page-locked buffer.\n");
        return ;
	}
	if (aux == count)
	printf("\n count: %d ", aux);
	times = fopen("mundzuk.dat","a");
	for (j = 0; j < count; j++){
		for (i = 0; i < DATASIZE; i++){
			host_cipher[i].v0 = cipher[j][0];
            host_cipher[i].v1 = cipher[j][1];
		}
		printf("\n cipher: %08lX %08lX   pt: %08lX %08lX \n", host_cipher[j].v0, host_cipher[j].v1, pt[j][1], pt[j][0]);	
		printf("\n Corriendo ataque %i ... \n", j); // indica la cantidad de ataques
		cipher_aux[j].v0 = host_cipher[j].v0;
		cipher_aux[j].v1 = host_cipher[j].v1;
		t1 = clock();
		for(x = 0x0; x <= 0x0000F010; x++){
			keya.k3 = (ulong)x;
			if (!tea_crypt((uchar*)host_cipher, DATASIZE * sizeof(TEA_BLOCK), (uchar*)host_cipher, keya, 1)){
    	        printf("ERROR en tea_decrypt()\n");   break;
		       }
			else{
				if (host_cipher[j].v0 == pt[j][1]){					
					if( host_cipher[j].v1 == pt[j][0] ){
						printf("key: %08lX %08lX %08lX %08lX", keya.k0, keya.k1, keya.k2, keya.k3);
						printf("  cifrado obtenido:  %08lX %08lX \n", host_cipher[j].v0, host_cipher[j].v1);
						printf("Clave encontrada con la GPU.\n");
						t1 = (clock()-t1)/CLOCKS_PER_SEC;
						fprintf(times,"%.3f\t %08lX \n", t1, x);
						break;
					}
				}
			}
			host_cipher[j].v0 = cipher_aux[j].v0;
			host_cipher[j].v1 = cipher_aux[j].v1;			
		}// fin for claves
	}
	fclose(times);
	cudaFreeHost(host_cipher);
	return;
}

void test_cuda(){
    cudaError_t ret;
    struct cudaDeviceProp cuda_devprop;
	int cudadev, cudadevcount;
	
	cudaGetDeviceCount(&cudadevcount);
	ret = cudaGetLastError();
    if (ret != cudaSuccess){
        printf("Error en la Tarjeta'%s'\n", cudaGetErrorString(ret));
        return;
    }
    
    printf("  TEA sobre CUDA con %i GPU:\n", cudadevcount);
    for (cudadev = 0; cudadev < cudadevcount; cudadev++){
        cudaGetDeviceProperties(&cuda_devprop, cudadev);
        printf("(%i) '%s'\n\n", cudadev, (char *)&cuda_devprop.name);
    }
    cudaGetDevice(&cudadev);
    if (ret != cudaSuccess){
        printf("Error en la Tarjeta.\n");
        return;
    }
//    printf("\n Datasize: %d \n", DATASIZE);
    return;
}
// crea los textos en claro
void plaintexts(){
	ulong i;
	ulong plaintext[2];
	plaintext[0] = 0x00000000;
	for(i = 0x0; i < NUMPT; i++){
		plaintext[1] = i;
		pt[i][0] = plaintext[0];
		pt[i][1] = plaintext[1];
		//printf("plaintext: %08lX %08lX \n", pt[i][1], pt[i][0]);
	}
}
// lee los textos en claro desde un archivo
void leer_plaintexts(){
	ulong i = 0;
	ulong plaintext[2];
	FILE *plain;
	plain = fopen (tea_plain, "r");
	if (! plain) {
		perror ("Error opening " tea_plain);
		exit (2);
	}
	while( !feof(plain) ){
		if( i == NUMPT) break;
		fscanf (plain, "%08lX %08lX", &(plaintext[0]), &(plaintext[1]));
		//printf("plaintext: %08lX %08lX \n", plaintext[0], plaintext[1]);
		pt[i][0] = plaintext[0];
		pt[i][1] = plaintext[1];
		i++;
	}	
}
