# xtea_cuda
A very old project, cryptoanalysis into xtea (Extended Tiny Encryption Algorithm) using CUDA capabilities. 
All the instructions are in spanish, for now. I created in 2009 for my final bachelor project.

NVCC or Nvidia CUDA compiler was used at the time.

To compile
  nvcc -o cutea tea_ataque.cu
	or 	nvcc -o cutea -Xptxas "-v" -maxrregcount=10 tea_ataque.cu

(in the future there's going to be a english version and also a non brute force attack code)
