'''
    Script to perform clustering using dynamic features;
    How to use:  pyhton3 clustering_process <day> <window> <path to feature file(s)>
    Example: time python3 clustering_process 1 10 day1/10min/*.csv
'''

import os
import warnings
from datetime import datetime
from pathlib import Path
from sys import argv, exit, version_info  
import time
import pandas as pd 
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering # Clustering Algorithms
from sklearn.preprocessing import MinMaxScaler # Data normalization libraries
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
import numpy as np
import plotly  
import plotly.graph_objs as go 
import gc # garbage colector to clean the memory
import joblib
from datetime import datetime

'''
    Global variables to merge data from different timewindows
    in which where detected suspicious entities (victims or attackers)
'''
save_clusters_victim, save_clusters_attacker = False, False
score_victims, list_all_windows = [], []
score_attackers, list_all_windows_attacker = [], []

'''
    Dictionary with victims and attackers IP addresses
    'day':['internal IP', 'external IP']
'''
victims = {'1':['172.31.69.25','18.217.21.148'], 
        '2':['172.31.69.25','18.217.21.148'],
        '3':['172.31.69.25','18.217.21.148'],
        '4':['172.31.69.25','18.217.21.148'], 
        '5':['172.31.69.28','18.218.83.150'],
        '6':['172.31.69.28','18.218.83.150'],
        '7':['172.31.69.28','18.218.83.150'], 
        '8':['172.31.69.24','18.221.148.137'], 
        '9':['172.31.69.13','18.216.254.154'],
        '10':['172.31.69.23','18.217.218.111','172.31.69.17','18.222.10.237','172.31.69.14','18.222.86.193','172.31.69.12','18.222.62.221', '172.31.69.10','13.59.9.106', '172.31.69.8','18.222.102.2', '172.31.69.6','18.219.212.0', '172.31.69.26','18.216.105.13', '172.31.69.29','18.219.163.126','172.31.69.30','18.216.164.12']}

attackers = {'1':['18.221.219.4','13.58.98.64'], 
        '2':['18.219.211.138','18.217.165.70'],
        '3':['13.59.126.31', '18.219.193.20'],
        '4':['18.218.115.60','18.219.9.1','18.219.32.43','18.218.55.126','52.14.136.135','18.219.5.43','18.216.200.189','18.218.229.235','18.218.11.51','18.216.24.42'],
        '5':['18.218.115.60','18.219.9.1','18.219.32.43','18.218.55.126','52.14.136.135','18.219.5.43','18.216.200.189','18.218.229.235','18.218.11.51','18.216.24.42'],
        '6':['18.218.115.60'],
        '7':['18.218.115.60'],
        '8':['13.58.225.34'],
        '9':['13.58.225.34'],
        '10':['18.219.211.138']}

'''
    Fuction to associate a file day to a day scale
'''
def get_day(file):
    if '14-02-18' in file:
        day=1
    if '15-02-18' in file:
        day=2
    if '16-02-18' in file:   
        day=3
    if '20-02-18' in file:
        day=4
    if '21-02-18' in file: 
        day=5
    if '22-02-18' in file:
        day=6
    if '23-02-18' in file:
        day=7
    if '28-02-18' in file:
        day=8
    if '01-03-18' in file:
        day=9
    if '02-03-18' in file:
        day=10
    return day

'''
    Function to select the timewindows of each day.
'''
def date(day):
    start_date = 0
    end_date = 0
    if day==1:
        # WEDNESDAY 14-02-2018
        start_date = datetime(2018,2,14,0,0,0)
        end_date = datetime(2018,2,15,0,0,0)
    if day==2:
        # THURSDAY 15-02-2018
        start_date = datetime(2018,2,15,0,0,0)
        end_date = datetime(2018,2,16,0,0,0)
    if day==3:
        # FRIDAY 16-02-2018
        start_date = datetime(2018,2,16,0,0,0)
        end_date = datetime(2018,2,17,0,0,0)    
    if day==4:
        # TUESDAY 20-02-2018
        start_date = datetime(2018,2,20,0,0,0)
        end_date = datetime(2018,2,21,0,0,0)
    if day==5:
        # WEDNESDAY 21-02-2018
        start_date = datetime(2018,2,21,0,0,0)
        end_date = datetime(2018,2,22,0,0,0)
    if day==6:
        # THURSDAY 22-02-2018
        start_date = datetime(2018,2,22,0,0,0)
        end_date = datetime(2018,2,23,0,0,0)
    if day==7:
        # FRIDAY 23-02-2018
        start_date = datetime(2018,2,23,0,0,0)
        end_date = datetime(2018,2,24,0,0,0)
    if day==8:
        # WEDNESDAY 28-02-2018
        start_date = datetime(2018,2,28,0,0,0)
        end_date = datetime(2018,3,1,0,0,0)
    if day==9:
        # THURSDAY 01-03-2018
        start_date = datetime(2018,3,1,0,0,0)
        end_date = datetime(2018,3,2,0,0,0)
    if day==10:
        # FRIDAY 02-03-2018
        start_date = datetime(2018,3,2,0,0,0)
        end_date = datetime(2018,3,3,0,0,0)
    return start_date, end_date

''' KMEANS e AGGLOMERATIVE
    Calculate the within-clusters sum-of-squares in KMeans,
    to further apply the elbow method:
     - k (number of cluster to find) of KMeans;
     - n_clusters (number of cluster to find) Agglomerative = k;
'''
def calculate_wcss(data):
    wcss = []
    for n in range(2,30): # test 2,3,4,..30 clusters and stores the distances intra-clusters
        kmeans = KMeans(n_clusters=n)
        kmeans.fit(X=data)
        wcss.append(kmeans.inertia_)
    return wcss

''' DBSCAN
    Calculates the distances among all entities;
    Sort them from lower to higher
'''
def distances_epsilon(data):
    neigh = NearestNeighbors(n_neighbors=2)
    nbrs = neigh.fit(data)
    distances, indices = nbrs.kneighbors(data)
    distances = np.sort(distances, axis=0)
    distances = distances[:,1]
    return distances
    

'''
    Function to generate clustering heatmaps
'''
def heat(name, newdf, file, day, window):
    out = newdf.groupby(['clusters',newdf.index]).count()
    n_clusters = out.index.to_frame(True, ['clusters','IPs'])
    if (len(newdf.index)> 600):
        aux = 'EXTERNAL'  #external 
        print('--EXTERNAL----'+str(name)+'-----'+str(file)+'-----------')
    else:
        aux = 'INTERNAL' # internal
        print('--INTERNAL----'+str(name)+'-----'+str(file)+'-----------')
    print(newdf['clusters'].value_counts())
    toz = newdf.groupby('clusters').mean()
    # delete columns without diferences
    toz = toz.loc[:, (toz > 0.2).any(axis=0)]
    print ("Start plot of matrix of shape: browser")

    data1 = [go.Heatmap(z=toz.values.tolist(),
                        y= list(toz.index.values),
                        x= list(toz),
                        colorscale='Viridis')]

    plotly.offline.plot(data1, filename = 'day'+str(day)+'/'+str(window)+'min/results/'+ aux +'_'+ os.path.basename(file) + 'heatmap.html')
    newdf = newdf.drop('clusters',axis=1)
    return newdf

'''
    Calculates the furthest point of the line from wcss of k= 2 with wcss=30;
    The furthest point represent the better k;
'''
def optimal_number_of_clusters(wcss):
    x1,y1 = 2, wcss[0]
    x2, y2 = 30, wcss[len(wcss)-1]
    distances = []
    for i in range(len(wcss)):
        x0 = i+2
        y0 = wcss[i]
        numerator = abs((y2-y1)*x0 - (x2-x1)*y0 + x2*y1 - y2*x1)
        denominator = np.sqrt((y2-y1)**2 + (x2-x1)**2)
        distances.append(numerator/denominator)
    return distances.index(max(distances)) + 2

    
'''
    Function to create clustering algorithms objects and  predict the respective cluster for each entity
'''
def clustering(dataframe, file, day, window):
    '''
        Data normalization into [0,1] scale - default values
        Other range can be used with MinMaxScaler(range=[-1,1])
    '''
    
    #delete zero columns
    dataframe = dataframe.loc[:, (dataframe != 0).any(axis=0)]
    print ("Start clustering matrix of shape:")
    print (dataframe.shape)
    
    norm = MinMaxScaler().fit_transform(dataframe)
    '''
        New dataframe to store the cluster number of each entity
        Dataframe of [#entities, #algorithm]
    '''
    new_df = pd.DataFrame(columns=['cluster_kmeans','cluster_dbscan','cluster_agglomerative'], index=dataframe.index[:len(norm)])
    '''
        Defining parameter k (# clusters) to KMeans and Agglomerative
        Condition to change parameter k, case the # of entities is lower than the parameter
    '''
    sum_of_squares = calculate_wcss(norm)

    n_clusters4kmeans = optimal_number_of_clusters(sum_of_squares)

    print('K : ', n_clusters4kmeans)

    epsilon = distances_epsilon(norm)

    index_epsilon = optimal_number_of_clusters(epsilon)

    epsilon = epsilon[index_epsilon-2]

    if epsilon <= 0:
        epsilon =0.3

    print('EPS : ', epsilon)

    tempo= time.time()
    '''
        Created the KMeans object and determines the clusters with normalized data
    '''
    kmeans = KMeans(n_clusters=n_clusters4kmeans).fit(norm).predict(norm)
    print('kmeans - ', time.time()-tempo)
    tempo= time.time()

    '''
        Call heatmap function from KMeans
    '''
    auxheat = pd.DataFrame(data=norm, columns=dataframe.columns, index=dataframe.index)
    auxheat['clusters'] = kmeans
    X = heat('KMEANS',auxheat, file, day, window) 
    '''
        Creates DBSCAN object and determine clusters with normalized data,
        From DBSCAN method:
            - eps -> parameter that indicates the maximum distance considered between two points in each neighbourhood;
            - min_samples -> minimum number of samples to consider as cluster;
            - n_jobs -> number of works in paralell. 
    '''
    dbscan = DBSCAN(eps=epsilon, min_samples=2, n_jobs=-1).fit_predict(norm)
    print('dbscan - ', time.time()-tempo)
    tempo= time.time()
    '''
        Creates an Agglomerative object and determines the clusters with normalized data
    '''
    agglometative = AgglomerativeClustering(n_clusters=n_clusters4kmeans).fit_predict(norm)
    print('agglometative - ', time.time()-tempo)
    tempo= time.time()
    '''
        Stores clusters info of each entity 
    '''
    new_df['cluster_kmeans'] = kmeans
    new_df['cluster_dbscan'] = dbscan
    new_df['cluster_agglomerative'] = agglometative

    '''
        Clean algorithm variables (only when gc.collect() is called)
    '''
    del dbscan, kmeans, norm,  agglometative
    gc.collect()
    print('donne clustering')
    ''' 
        Returns a dataframe with clusters information
    '''
    return new_df

'''
    Function for result analisys, apply metric (True Positives, False Positives, True Negatives, False Negatives)
'''
def result_analysis(df, file, windows, view, day, df_features):
    #del df.index.name
    '''
        Uses global variables:
            - victims, attackers -> collects informaticon according the day
            - score_victims, score_attackers -> variables used to store in each timewindow the different scores by entity
            - save_clusters_victim, save_clusters_attacker, list_all_windows, list_all_windows_attacker -> variables to compile the information of all timewindows on a single file
    '''
    global victims, attackers
    global score_victims, score_attackers
    global save_clusters_victim, save_clusters_attacker, list_all_windows, list_all_windows_attacker
    '''
        Path to store the results
    '''
    file_prefix = 'day'+str(day)+'/'+str(windows)+'min/results/'+str(view)+'_'+str(file).split('.')[0].split('/')[-1]
    
    '''
        Search for victims and attackers acording to the processsed day
    '''
    n_victims = 0
    for victim in victims[str(day)]:
        if victim in df.index:
            n_victims +=1
            save_clusters_victim = True
            df.loc[victim].to_csv(file_prefix +'_' +str(df.loc[victim].name)+'_victim'+ '.csv', header= True)
    print('# Victims found - ', n_victims)
    n_attackers = 0
    for attacker in attackers[str(day)]:
        if attacker in df.index:
            n_attackers += 1
            save_clusters_attacker = True
            df.loc[attacker].to_csv(file_prefix +'_'+str(df.loc[attacker].name) + '_attacker' +'.csv', header= True)
    print('# Attackers Found - ', n_attackers)
    '''
        Case victims or attackers are founded
    '''
    if (save_clusters_victim==True) or (save_clusters_attacker==True):
        print('saving files')
        '''
            Stores information about the clusters in separated files identified by the timewindow and algorithm
        '''
        df['cluster_kmeans'].to_csv(file_prefix + '_kmeans.csv', header=True)
        df['cluster_dbscan'].to_csv(file_prefix +'_dbscan.csv', header=True)
        df['cluster_agglomerative'].to_csv(file_prefix+'_agglomerative.csv', header=True)
        '''
            Select outlier cluster from DBSCN
        '''
        lof_clusters = df[df['cluster_dbscan'].values == -1]
        lof_clusters = lof_clusters['cluster_dbscan']
        '''
            Stores the total number of entities for each cluster and each algorithm
        '''
        ncluster_kmeans = df.groupby('cluster_kmeans')['cluster_dbscan'].count().to_frame() 
        ncluster_dbscan = df.groupby('cluster_dbscan')['cluster_kmeans'].count().to_frame() 
        ncluster_agglomerative = df.groupby('cluster_agglomerative')['cluster_kmeans'].count().to_frame()
        '''
            Select the clusters with # of entities <= 1 and outlier clusters in desity based algorithms (DBSCAN)
        '''
        ncluster_kmeans_ = ncluster_kmeans[ncluster_kmeans.values <= 1]
        ncluster_dbscan_ = ncluster_dbscan[ncluster_dbscan.values <= 1]
        if '-1' not in str(ncluster_dbscan_.index) and ncluster_dbscan.index.values.min()<0:
            ncluster_dbscan_.at['100'] = (ncluster_dbscan[ncluster_dbscan.index < 0].values[0])
        ncluster_agglomerative_ = ncluster_agglomerative[ncluster_agglomerative.values <= 1]

        cluster_results_victim = pd.DataFrame()

        '''
            Victims analysis
        '''
        for victim in victims[str(day)]:
            '''
                Stores for each algorithm: # and size of victim's cluster 
            '''
            if victim in df.index:
                cluster_results_victim.at[victim,'cluster_kmeans'] = int(df.loc[victim,'cluster_kmeans'])
                cluster_results_victim.at[victim,'cluster_kmeans_size'] = int(ncluster_kmeans.loc[df.loc[victim,'cluster_kmeans']][0])
                cluster_results_victim.at[victim,'cluster_dbscan'] = int(df.loc[victim,'cluster_dbscan'])
                cluster_results_victim.at[victim,'cluster_dbscan_size'] = int(ncluster_dbscan.loc[df.loc[victim,'cluster_dbscan']][0])
                cluster_results_victim.at[victim,'cluster_agglomerative'] = int(df.loc[victim,'cluster_agglomerative'])
                cluster_results_victim.at[victim,'cluster_agglomerative_size'] = int(ncluster_agglomerative.loc[df.loc[victim,'cluster_agglomerative']][0])
        '''
            Get the cluster number where victims belong to use as dataframes index ('victims_kmeans', 'victims_dbscan', 'victims_aglomerative' )
        '''
        if len(cluster_results_victim)>0:
            index_count_victims=[]
            index_count_victims.append(cluster_results_victim['cluster_kmeans'].values.tolist())
            index_count_victims.append(cluster_results_victim['cluster_dbscan'].values.tolist())
            index_count_victims.append(cluster_results_victim['cluster_agglomerative'].values.tolist())
            index_count_victims = [item for sublist in index_count_victims for item in sublist]
            victims_kmeans = pd.DataFrame(index=set(index_count_victims),columns=['victims_kmeans','kmeans_size','window'])
            victims_dbscan = pd.DataFrame(index=set(index_count_victims),columns=['victims_dbscan','dbscan_size','window'])
            victims_agglomerative = pd.DataFrame(index=set(index_count_victims),columns=['victims_agglomerative','agglomerative_size', 'window'])
            '''
                Dataframe to store the results with the metrics defined bellow
            '''
            scores = pd.DataFrame(columns=['kmeans','dbscan','agglomerative'])

            for victim in victims[str(day)]:
                '''
                    Filters the clusters with one entitie (for Agglomerative and KMeans) and outlier cluster (DBSCAN)
                '''
                if victim in cluster_results_victim.index:
                    if cluster_results_victim.loc[victim]['cluster_kmeans_size'] <= 1:
                        victims_kmeans.at[cluster_results_victim.loc[victim,'cluster_kmeans'],'victims_kmeans'] = cluster_results_victim['cluster_kmeans'].value_counts().loc[cluster_results_victim.loc[victim]['cluster_kmeans']]
                        victims_kmeans.at[cluster_results_victim.loc[victim,'cluster_kmeans'],'kmeans_size'] = cluster_results_victim.loc[victim]['cluster_kmeans_size']
                    if cluster_results_victim.loc[victim]['cluster_dbscan'] == -1 or cluster_results_victim.loc[victim]['cluster_dbscan_size'] == 1:
                        victims_dbscan.at[cluster_results_victim.loc[victim,'cluster_dbscan'],'victims_dbscan'] = cluster_results_victim['cluster_dbscan'].value_counts().loc[cluster_results_victim.loc[victim,'cluster_dbscan']]
                        victims_dbscan.at[cluster_results_victim.loc[victim,'cluster_dbscan'],'dbscan_size'] = cluster_results_victim.loc[victim]['cluster_dbscan_size']
                    if cluster_results_victim.loc[victim]['cluster_agglomerative_size'] <= 1:
                        victims_agglomerative.at[cluster_results_victim.loc[victim,'cluster_agglomerative'],'victims_agglomerative'] = cluster_results_victim['cluster_agglomerative'].value_counts().loc[cluster_results_victim.loc[victim,'cluster_agglomerative']]
                        victims_agglomerative.at[cluster_results_victim.loc[victim,'cluster_agglomerative'],'agglomerative_size'] = cluster_results_victim.loc[victim]['cluster_agglomerative_size']
            victims_agglomerative['window'] = 11111
            victims_agglomerative.fillna(value=0, inplace=True)
            victims_kmeans['window'] = 1111
            victims_kmeans.fillna(value=0, inplace=True)
            victims_dbscan['window'] = 11111
            victims_dbscan.fillna(value=0, inplace=True)
            '''
                Number of victims detected by algorithm
            '''
            scores['kmeans'] = victims_kmeans['victims_kmeans']
            scores['dbscan'] = victims_dbscan['victims_dbscan']
            scores['agglomerative'] = victims_agglomerative['victims_agglomerative']
            scores.at['tot_kmeans'] = scores.iloc[:len(victims_kmeans.index)]['kmeans'].sum()
            scores.at['tot_dbscan'] = scores.iloc[:len(victims_dbscan.index)]['dbscan'].sum()
            scores.at['tot_agglomerative'] = scores.iloc[:len(victims_agglomerative.index)]['agglomerative'].sum()
            scores.fillna(value=0, inplace=True)
            
            '''
                Count number of entities and victims per cluster in each algorithm
            '''
            for algorithm in scores.columns:
                if str(algorithm) == 'kmeans':
                    ncluster = ncluster_kmeans_.values.sum()
                    count_victims = victims_kmeans['victims_kmeans']
                elif str(algorithm) == 'dbscan':
                    ncluster = ncluster_dbscan_.values.sum()
                    count_victims = victims_dbscan['victims_dbscan']
                else:
                    ncluster = ncluster_agglomerative_.values.sum()
                    count_victims = victims_agglomerative['victims_agglomerative']
                print(algorithm + ' :')
                print(ncluster)
                '''
                    Apply the metrics:
                    -    True Positices (TP) -  entities correctly classified as outliers;
                    -    False Positives (FP) - entities wrongly classified as outliers;
                    -    True Negatives (TN) - entities correctly classified as 'normal';
                    -    False Negatives (FN) - entities wrongly classified as 'normal';
                    -    Accuracy - (TP+TN)/(TP+TN+FP+FN);
                    -    Precision - TP/(TP+FP);
                    -    Recall - TP/(TP+FN);
                    -    F1 - 2*(Precision*Recall)/(Precision+Recall).
                '''
                scores.at['#TP',algorithm] = scores.loc['tot_'+algorithm,algorithm]
                scores.at['#FP',algorithm] = ncluster-count_victims.values.sum()
                scores.at['#TN',algorithm] = len(df.index)-ncluster
                scores.at['#FN',algorithm] = len(df.index)-scores.loc['#TP',algorithm]-scores.loc['#FP',algorithm]-scores.loc['#TN',algorithm]
                scores.at['Accuracy',algorithm] = (scores.loc['#TP',algorithm]+scores.loc['#TN',algorithm])/(scores.loc['#TP',algorithm]+scores.loc['#TN',algorithm]+scores.loc['#FN',algorithm]+scores.loc['#FP',algorithm])
                '''
                    Condition to avoid divisons by zero
                '''
                if (scores.loc['#TP',algorithm] == 0 and scores.loc['#FP',algorithm]== 0) or (scores.loc['#FN',algorithm] == 0 and scores.loc['#TP',algorithm]==0):
                    scores.at['Precision',algorithm]= 0
                    scores.at['Recall',algorithm] = 0
                    scores.at['F1'] = 0
                else:
                    scores.at['Precision',algorithm] = scores.loc['#TP',algorithm]/(scores.loc['#TP',algorithm]+scores.loc['#FP',algorithm])
                    scores.at['Recall',algorithm] = scores.loc['#TP',algorithm]/(scores.loc['#TP',algorithm]+scores.loc['#FN',algorithm])
                    scores.at['F1'] = 2*(scores.loc['Precision',algorithm]*scores.loc['Recall',algorithm])/(scores.loc['Recall',algorithm]+scores.loc['Precision',algorithm])
            '''
                Apply LOF to outlier cluster identified by '100'
            '''
            lof_scores = pd.DataFrame(index=lof_clusters.index, columns=['score'])
            if len(lof_clusters.index) <= 5:
                lof = np.zeros(len(lof_clusters.index))
                lof_scores.at[:,'score'] = lof
            else:
                lof = LocalOutlierFactor(n_neighbors = 5, contamination=0.01)
                lof.fit_predict(df_features.loc[lof_clusters.index])
                lof_scores.at[:,'score'] = lof.negative_outlier_factor_
            ''' 
                LOF score is negative, the more negative the greater the probability of being an outlier
                then the min () corresponds to the identified entity most likely to be outlier
            '''
            scores.at['Max_score'] = [0,lof_scores.min().values,0] 
            '''
                Retrives LOF score for each victim,
                In the analysis, the MAX_SCORE is compared with the scores of each victim
            '''
            for victim in victims[str(day)]:
                if victim in lof_scores.index:
                    scores.at[str(victim)] = lof_scores.loc[str(victim)].values
            scores.at['Time'] = 1111
            score_victims.append(scores)

        '''
            Attackers analysis
        '''
        cluster_results_attacker = pd.DataFrame()

        for attacker in attackers[str(day)]:
            '''
                Stores for each algorithm: # and size of attacker's cluster 
            '''
            if attacker in df.index:
                cluster_results_attacker.at[attacker,'cluster_kmeans'] = int(df.loc[attacker,'cluster_kmeans'])
                cluster_results_attacker.at[attacker,'cluster_kmeans_size'] = int(ncluster_kmeans.loc[df.loc[attacker,'cluster_kmeans']][0])
                cluster_results_attacker.at[attacker,'cluster_dbscan'] = int(df.loc[attacker,'cluster_dbscan'])
                cluster_results_attacker.at[attacker,'cluster_dbscan_size'] = int(ncluster_dbscan.loc[df.loc[attacker,'cluster_dbscan']][0])
                cluster_results_attacker.at[attacker,'cluster_agglomerative'] = int(df.loc[attacker,'cluster_agglomerative'])
                cluster_results_attacker.at[attacker,'cluster_agglomerative_size'] = int(ncluster_agglomerative.loc[df.loc[attacker,'cluster_agglomerative']][0])
        '''
            Get the cluster number where victims belong to use as dataframes index ('attackers_kmeans', 'attackers_dbscan', 'attackers_aglomerative')
        '''
        if len(cluster_results_attacker)>0:
            index_count_attacker=[]
            index_count_attacker.append(cluster_results_attacker['cluster_kmeans'].values.tolist())
            index_count_attacker.append(cluster_results_attacker['cluster_dbscan'].values.tolist())
            index_count_attacker.append(cluster_results_attacker['cluster_agglomerative'].values.tolist())
            index_count_attacker = [item for sublist in index_count_attacker for item in sublist]            
            attackers_kmeans = pd.DataFrame(index=set(index_count_attacker),columns=['attackers_kmeans','kmeans_size','window'])
            attackers_dbscan = pd.DataFrame(index=set(index_count_attacker),columns=['attackers_dbscan','dbscan_size','window'])
            attackers_agglomerative = pd.DataFrame(index=set(index_count_attacker),columns=['attackers_agglomerative','agglomerative_size', 'window'])
            '''
                Dataframe to store the results with the metrics defined bellow
            '''
            scores = pd.DataFrame(index=set(index_count_attacker), columns=['kmeans','dbscan','agglomerative'])
            true_negatives, false_negatives=[],[]
            for attacker in attackers[str(day)]:
                '''
                    Filters the clusters with one entitie (for Agglomerative and KMeans) and outlier cluster (DBSCAN)
                '''
                if attacker in cluster_results_attacker.index:
                    if cluster_results_attacker.loc[attacker]['cluster_kmeans_size'] <= 1:
                        attackers_kmeans.at[cluster_results_attacker.loc[attacker,'cluster_kmeans'],'attackers_kmeans'] = cluster_results_attacker['cluster_kmeans'].value_counts().loc[cluster_results_attacker.loc[attacker]['cluster_kmeans']]
                        attackers_kmeans.at[cluster_results_attacker.loc[attacker,'cluster_kmeans'],'kmeans_size'] = cluster_results_attacker.loc[attacker]['cluster_kmeans_size']
                    if cluster_results_attacker.loc[attacker]['cluster_dbscan'] == -1 or cluster_results_attacker.loc[attacker]['cluster_dbscan_size'] == 1:
                        attackers_dbscan.at[cluster_results_attacker.loc[attacker,'cluster_dbscan'],'attackers_dbscan'] = cluster_results_attacker['cluster_dbscan'].value_counts().loc[cluster_results_attacker.loc[attacker,'cluster_dbscan']]
                        attackers_dbscan.at[cluster_results_attacker.loc[attacker,'cluster_dbscan'],'dbscan_size'] = cluster_results_attacker.loc[attacker]['cluster_dbscan_size']
                    if cluster_results_attacker.loc[attacker]['cluster_agglomerative_size'] <= 1:
                        attackers_agglomerative.at[cluster_results_attacker.loc[attacker,'cluster_agglomerative'],'attackers_agglomerative'] = cluster_results_attacker['cluster_agglomerative'].value_counts().loc[cluster_results_attacker.loc[attacker,'cluster_agglomerative']]
                        attackers_agglomerative.at[cluster_results_attacker.loc[attacker,'cluster_agglomerative'],'agglomerative_size'] = cluster_results_attacker.loc[attacker]['cluster_agglomerative_size']
            attackers_agglomerative['window'] = 1111
            attackers_agglomerative.fillna(value=0, inplace=True)
            attackers_dbscan['window'] = 1111
            attackers_dbscan.fillna(value=0, inplace=True)
            attackers_kmeans['window'] = 1111
            attackers_kmeans.fillna(value=0, inplace=True)
            '''
                Number of attacker detected for each algorithm
            '''
            scores['kmeans'] = attackers_kmeans['attackers_kmeans']
            scores['dbscan'] = attackers_dbscan['attackers_dbscan']
            scores['agglomerative'] = attackers_agglomerative['attackers_agglomerative']
            scores.at['tot_kmeans'] = scores.iloc[:len(attackers_kmeans.index)]['kmeans'].sum()
            scores.at['tot_dbscan'] = scores.iloc[:len(attackers_dbscan.index)]['dbscan'].sum()
            scores.at['tot_agglomerative'] = scores.iloc[:len(attackers_agglomerative.index)]['agglomerative'].sum()
            scores.fillna(value=0, inplace=True)
            '''
               Count number of entities and attackers per cluster in each algorithm
            '''
            for algorithm in scores.columns:
                if str(algorithm) == 'kmeans':
                    ncluster = ncluster_kmeans_.values.sum()
                    count_attacker = attackers_kmeans['attackers_kmeans']
                elif str(algorithm) == 'dbscan':
                    ncluster = ncluster_dbscan_.values.sum()
                    count_attacker = attackers_dbscan['attackers_dbscan']
                elif str(algorithm) == 'agglomerative':
                    ncluster = ncluster_agglomerative_.values.sum()
                    count_attacker = attackers_agglomerative['attackers_agglomerative']
                print(str(algorithm) + ' :')
                print(ncluster)
                '''
                    Apply the metrics:
                    -    True Positices (TP) -  entities correctly classified as outliers;
                    -    False Positives (FP) - entities wrongly classified as outliers;
                    -    True Negatives (TN) - entities correctly classified as 'normal';
                    -    False Negatives (FN) - entities wrongly classified as 'normal';
                    -    Accuracy - (TP+TN)/(TP+TN+FP+FN);
                    -    Precision - TP/(TP+FP);
                    -    Recall - TP/(TP+FN);
                    -    F1 - 2*(Precision*Recall)/(Precision+Recall).
                '''
                scores.at['#TP',algorithm] = scores.loc['tot_'+algorithm,algorithm]
                scores.at['#FP',algorithm] = ncluster-count_attacker.values.sum()
                scores.at['#TN',algorithm] = len(df.index)-ncluster
                scores.at['#FN',algorithm] = len(df.index)-scores.loc['#TP',algorithm]-scores.loc['#FP',algorithm]-scores.loc['#TN',algorithm]
                scores.at['Accuracy',algorithm] = (scores.loc['#TP',algorithm]+scores.loc['#TN',algorithm])/(scores.loc['#TP',algorithm]+scores.loc['#TN',algorithm]+scores.loc['#FN',algorithm]+scores.loc['#FP',algorithm])
                '''
                    Condition to avoid divison by zero
                '''
                if (scores.loc['#TP',algorithm] == 0 and scores.loc['#FP',algorithm]== 0) or (scores.loc['#FN',algorithm] == 0 and scores.loc['#TP',algorithm]==0):
                    scores.at['Precision',algorithm]= 0
                    scores.at['Recall',algorithm] = 0
                    scores.at['F1'] = 0
                else:
                    scores.at['Precision',algorithm] = scores.loc['#TP',algorithm]/(scores.loc['#TP',algorithm]+scores.loc['#FP',algorithm])
                    scores.at['Recall',algorithm] = scores.loc['#TP',algorithm]/(scores.loc['#TP',algorithm]+scores.loc['#FN',algorithm])
                    scores.at['F1'] = 2*(scores.loc['Precision',algorithm]*scores.loc['Recall',algorithm])/(scores.loc['Recall',algorithm]+scores.loc['Precision',algorithm])
            '''
                Apply LOF to outlier cluster identified as "100"
            '''
            lof_scores = pd.DataFrame(index=lof_clusters.index, columns=['score'])
            if len(lof_clusters.index) <= 5 or len(lof_clusters.index) == 0:
                lof = np.zeros(len(lof_clusters.index))
                lof_scores.at[:,'score'] = lof
            else:
                lof = LocalOutlierFactor(n_neighbors = 5, contamination=0.01)
                lof.fit_predict(df_features.loc[lof_clusters.index])
                lof_scores.at[:,'score'] = lof.negative_outlier_factor_
            ''' 
                LOF score is negative, the more negative the greater the probability of being an outlier
                then the min () corresponds to the identified entity most likely to be outlier
            '''
            scores.at['Max_score'] = [0,lof_scores.min().values,0]
            
            '''
                Retrives LOF score for each attacker,
                In the analysis, the MAX_SCORE is compared with the scores of each victim
            '''
            for attacker in attackers[str(day)]:
                if attacker in lof_scores.index:
                    scores.at[str(attacker)] = lof_scores.loc[str(attacker)].values
            scores.at['Time'] = 1111
            score_attackers.append(scores)
            count_attacker.fillna(value=0, inplace=True)

    save_clusters_attacker = False
    save_clusters_victim = False
    del file_prefix, df
    gc.collect()


def main():
    global save_clusters_attacker, save_clusters_victim
    '''
        CSV file with features
    '''
    files_features = argv[3:]
    '''
        Timewindow to analyze
    '''
    day = int(argv[1])
    window = int(argv[2])
    dir_path = os.path.dirname(os.path.realpath(str(argv[1]))) 
    Path(str(dir_path)+'/day'+str(day)+'/'+str(window)+'min/results/').mkdir(parents=True, exist_ok=True)
    
    for file in files_features:
        tempo =time.time()
        df_timestamp = []
        '''
            Loads the file by chunks to dataframe
        '''
        for chunk in pd.read_csv(file, sep=',', dtype='object', chunksize=100000):
            df_timestamp.append(chunk)

        df_timestamp = pd.concat(df_timestamp)
        print("Donne reading csv")
        df_timestamp.set_index(df_timestamp.iloc[:,0], inplace=True)
        df_timestamp.drop(['Unnamed: 0'], axis=1 , inplace=True)
        #del df_timestamp.index.name
        # Apply clustering algorithms
        if len(df_timestamp.index) > 0:
            src_df, dst_df = [],[]
            for ind in df_timestamp.index:
                if '172.31.' in str(ind):
                    src_df.append(ind)
                else:
                    dst_df.append(ind)
            src_df = df_timestamp.loc[src_df]
            dst_df = df_timestamp.loc[dst_df]
            if len(src_df.index) >= 30: # LD estava 10
                clusters_src = clustering(src_df, file, day, window)
                result_analysis(clusters_src, file, window, 'internal', day, src_df)
            else:
                print('SRC not saved')

            if len(dst_df.index) >= 30: #LD estava 10
                clusters_dst = clustering(dst_df, file,day, window)
                result_analysis(clusters_dst, file, window, 'external', day, dst_df)
            else:
                print('DST not saved')
        else:
            print("Time stamp not found")
        '''
            Store results in CSV files;
            Folders for each day, timewindow and approaches must be created before execute the script
            Example for day 2 - ../dia2/10min/results_dynamic/..._scores_victims_new.csv
        '''
    if len(score_victims) > 0:
        pd.concat(score_victims).to_csv('day'+str(day)+'/'+str(window)+'min/results/'+str(file).split('.')[0].split('/')[-1]+'_scores_victims_new.csv', header=True)
    if len(score_attackers) > 0:
        pd.concat(score_attackers).to_csv('day'+str(day)+'/'+str(window)+'min/results/'+str(file).split('.')[0].split('/')[-1]+'_scores_attackers_new.csv', header=True)
    print(str(file) + ' extracted')

if __name__ == '__main__':
    main()
