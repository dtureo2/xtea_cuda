# xtea_cuda
A very old project, cryptoanalysis into xtea (Extended Tiny Encryption Algorithm) using CUDA capabilities. 
All the instructions are in spanish, for now. I created in 2009 for my final bachelor project.

It would be worth to try
  nvcc -o cuda tea_ataque.cu'
	or 	nvcc -o gpu_ataque -Xptxas "-v" -maxrregcount=10 tea_ataque.cu

(in the future there's going to be a english version and also a non brute force attack code)
