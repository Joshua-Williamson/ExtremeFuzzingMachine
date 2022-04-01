How to use this testing folder becaue u will forget:
--------------------------------------------------

Testing vanilla neuzz:
-copy all the seed files into /seeds ass wella s the binary in to the testing directory.
$python vanilla_nntest.py ./<target program>
-Outputs will show testing and training accuracies 

Testing ELMneuzz:
-copy all the seed files into /seeds ass wella s the binary in to the testing directory.
$python nntest.py ./<target program>
-Outputs will show testing and training accuracies 

Comparing gradients line by line:
-copy the hard_label.hd5 from the neuzz training into the dir as well
-run the steps of testing ELMneuzz 
-then run the gradient compare