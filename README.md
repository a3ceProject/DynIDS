# DynIDS

In this repository you can find 2 scripts (feature_extractor.py and clustering_process.py).
It also contains a folder with example data ("Output Example"), and a small dataset (need to uncompress the .zip file) to test the scripts. 

Full dataset (from CICIDS2018* dataset) can be found here: https://drive.google.com/file/d/1YqzvY7MdbxIvkbdoVAA_umYW_XtPKQBi/view?usp=sharing

* https://www.unb.ca/cic/datasets/ids-2018.html

Scripts prerequisites:
  - Python 3
  - Pandas (https://pandas.pydata.org/getting_started.html)
  - Numpy (https://numpy.org)
  - Sklearn (https://scikit-learn.org/stable/index.html)
  - Plotly (https://plotly.com/)


You will also need permission to create folders in your working directory.
  
################## feature_extractor.py ##################

The feature_extractor.py script is used to extract the features from a CSV file with traffic information (bidirectional flows).
This script receives the CSV file as input (e.g., 14-02-18_ftp_bruteforce_partial.csv* ) and returns CSV files (stored in folder "day1"), one per timewindow, with the features extracted and organized by entities (IP addresses).

*partial file from the CICIDS2018 dataset. The input file can be from other netflow data (e.g., real scenario), as long as the data format is the same.

The features can be selected from 3 methods:

  0 - Outgene features

  1 - DYN3_x is the default (the DynIDS algorithm): features based on the x/3
      ports that appear in more more flows, the x/3 ports that appear
      in fewer flows, and the x/3 ports used by fewer machines.
  
  2 - Flowhacker (DOI: 10.1109/TrustCom/BigDataSE.2018.00086)

NOTE: to change the method and other parameters (e.g., size of time-windows - default is 30 minutes), run "python3 feature_extractor.py" from command line and folow the instructions.

Usage example (from command line):

  Linux/MAC OS:
    
    - python3 feature_extractor.py 14-02-18_ftp_bruteforce_partial.csv
  
################## clustering_process.py ##################

The clustering_process.py script is used to perform clustering using as input the features files created by feature_extractor.py script.
This script receives the CSV files with features (ex:30_features_1_10/00/00.csv) and returns CSV files with clustering results.

To evaluate the approaches some metrics were defined:

    - True Positices (TP) -  entities correctly classified as outliers
    
    - False Positives (FP) - entities wrongly classified as outliers
    
    - True Negatives (TN) - entities correctly classified as 'normal'
    
    - False Negatives (FN) - entities wrongly classified as 'normal'
    
    - Accuracy - (TP+TN)/(TP+TN+FP+FN)
    
    - Precision - TP/(TP+FP)
    
    - Recall - TP/(TP+FN)
    
    - F1 - 2*(Precision*Recall)/(Precision+Recall)
    
The output files contain the clustering results for both external and internal IPs (both processed separately), and metrics evaluation according to the entities considered outliers (attackers and/or victims of CIC-IDS-2018). 

Usage example (from command line):
  
  Linux/MAC OS:
    
    - python3 clustering_process.py <day> <timewindow> <features file(s)>
    - python3 clustering_process.py 1 30 day1/30min/*.csv   # To analyse the features of all 30min timewindows
    - python3 clustering_process.py 1 30 day1/30min/30_features_1_10/00/00.csv # To analyse a specific 30min timewindow
 


# DynIDS

L. Dias, S. Valente, and M. Correia, “Go With the Flow: Clustering Dynamically-Defined NetFlow Features for
Network Intrusion Detection with DYNIDS”, In Proceedings of the 19th IEEE International Symposium on Network
Computing and Applications (NCA), Nov. 2020
