# DefineIDS

In this repository you can find 2 scripts (feature_extractor.py and clustering_process.py).
It also contains a folder with example input and output files.

Scripts prerequisites:
  - Python 3
  - Pandas (https://pandas.pydata.org/getting_started.html)
  - Numpy (https://numpy.org)
  - Sklearn (https://scikit-learn.org/stable/index.html)

You will also need permission to create folders in your working directory.
  
################## feature_extractor.py ##################

The feature_extractor.py script is used to extract the features from a file CSV file with traffic information (flows).
This script receives the CSV file as input (ex:14-02-18_ftp_bruteoforce) and returns CSV files, one per timewindow, with the features extracted and organized by entities (IP addresses).

The features can be selected from 4 methods:
  1 - Outgene features
  2 - 50-50
  3 - Top-Uncommmon-Min (default) 
  4 - Test
NOTE: to change the method go to line 110 in the script, change and save it.

Usage example (from command line):
Linux/MAC OS:
  - python3 feature_extractor.py 14-02-18_ftp_bruteoforce.csv
  
################## clustering_process.py ##################

The clustering_process.py script is used to perform clustering using as input the features files created by feature_extractor.py script.
This script receives the CSV files with features (ex:10_features_1_10/00/00.csv) and returns CSV files with clustering results.

To evaluate the approaches some metrics were defined:
    -    True Positices (TP) -  entities correctly classified as outliers;
    -    False Positives (FP) - entities wrongly classified as outliers;
    -    True Negatives (TN) - entities correctly classified as 'normal';
    -    False Negatives (FN) - entities wrongly classified as 'normal';
    -    Accuracy - (TP+TN)/(TP+TN+FP+FN);
    -    Precision - TP/(TP+FP);
    -    Recall - TP/(TP+FN);
    -    F1 - 2*(Precision*Recall)/(Precision+Recall).
    
The output files contain the metrics evaluation to the entities considered outliers (attackers and/or victims).

Usage example (from command line):
Linux/MAC OS:
  - python3 clustering_process.py day1/10min/*.csv   # To analyse the features of all 10min timewindows
  - python3 clustering_process.py day1/10min/10_features_1_10/00/00.csv # To analyse a specific 10min timewindow
  
  
