'''
    Script para aplicar clustering com as features dinamicas;
    Como usar:  pyhton3 clustering_process <day> <window> <caminho para ficheiros com as features>
    Exemplo: time python3 clustering_process 1 10 day1/10min/*.csv
'''
import sys #Para ler da linha de comandos
import time
import pandas as pd # Manipular os dados
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering # Algoritmos de clustering
from sklearn.preprocessing import MinMaxScaler # Biblioteca para normalizacao de dados
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
import numpy as np
import plotly  #LD Heatmap
import plotly.graph_objs as go #LD Heatmap
import gc # garbage colector para limpar memoria
import joblib
from datetime import datetime
import os
'''
    Conjunto de variaveis globais para compilar dados das diferentes janelas temporais
    em que foram detetadas entidades anomalas (vitimas ou atacantes)
'''
save_clusters_victim, save_clusters_attacker = False, False
score_victims, list_all_windows = [], []
score_attackers, list_all_windows_attacker = [], []

'''
    Dicionários com os IPs das vitimas e atacantes
    'dia':['IPinterno', 'IPexterno']
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
    Funcao para associar o dia do ficheiro a uma escala de dias
'''
def get_day(file):
    if '14-02-18' in file:
        day=1
    if '15-02-18' in file:
        day=2
    if '16-02-18' in file:   #ficheiro que nao da para sacar features
        day=3
    if '20-02-18' in file:
        day=4
    if '21-02-18' in file:  #ficheiro que nao da para sacar features
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
    Funcao para restringir as janelas de tempo ao respetivo dia, porque existem eventos/flows com datas anteriores/posteriores ao dia em análise.
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
    Determinar o within-clusters sum-of-squares para o KMeans,
    para aplicar o metodo elbow:
     - k (numero de clusters a encontrar) do KMeans;
     - n_clusters (numero de clusters a encontrar) Agglomerative = k;
'''
def calculate_wcss(data):
    wcss = []
    for n in range(2,30): # testa 2,3,4,..30 clusters e armazena as distancias intra clusters
        kmeans = KMeans(n_clusters=n)
        kmeans.fit(X=data)
        wcss.append(kmeans.inertia_)
    return wcss

''' DBSCAN
    Determina as distancias entre as todas as entidades;
    Organiza-as da mais pequena a maior;
'''
def distances_epsilon(data):
    neigh = NearestNeighbors(n_neighbors=2)
    nbrs = neigh.fit(data)
    distances, indices = nbrs.kneighbors(data)
    distances = np.sort(distances, axis=0)
    distances = distances[:,1]
    return distances
    

'''
Função para gerar heatmaps do clustering
'''
def heat(name, newdf, file, day, window):
    #Numero de entidades por cluster:
    out = newdf.groupby(['clusters',newdf.index]).count()
    n_clusters = out.index.to_frame(True, ['clusters','IPs'])
    if (len(newdf.index)> 600):
        aux = 'EXTERNO'  #externo
        print('--EXTERNO----'+str(name)+'-----'+str(file)+'-----------')
    else:
        aux = 'INTERNO' # interno
        print('--INTERNO----'+str(name)+'-----'+str(file)+'-----------')
    print(newdf['clusters'].value_counts())
    toz = newdf.groupby('clusters').mean()
    #eliminar colunas sem diferenças
    toz = toz.loc[:, (toz > 0.2).any(axis=0)]
    print ("Start plot of matrix of shape: browser")
#    toz = toz.reindex(sorted(toz.columns, key=lambda x: str(x[-5])), axis=1)
#    toz = toz.reindex(sorted(toz.columns, key=lambda x: str(x[1:])), axis=1)
#    print (toz.shape)

    data1 = [go.Heatmap(z=toz.values.tolist(),
                        y= list(toz.index.values),
                        x= list(toz),
                        colorscale='Viridis')]

    plotly.offline.plot(data1, filename = 'day'+str(day)+'/'+str(window)+'min/results_dynamic/'+ aux +'_'+ os.path.basename(file) + 'heatmap.html')
#    sns.heatmap(toz, cmap='RdYlGn_r', linewidths=0.5, annot=True)
   
#    sns.heatmap(toz, annot=True)
#    plt.show()
    #print(newdf.loc[["'10.105.1.131'"],['clusters']])
    newdf = newdf.drop('clusters',axis=1)
    return newdf


'''
    Calcula o ponto mais distante da linha que une a wcss de k=2 com a wcss k=30;
    O ponto mais distance representa o melhor k;
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
    Função para criar objetos dos algoritmos de clustering e predizer os respetivos clusters para cada entidade
'''
def clustering(dataframe, file, day, window):
    '''
        Normalizacao dos dados para uma escala entre [0,1] - valores por defeito
        Pode ser usado outro range com MinMaxScaler(range=[-1,1])
    '''
    
    #apagar colunas a zero LD
    dataframe = dataframe.loc[:, (dataframe != 0).any(axis=0)]
    print ("Start clustering matrix of shape:")
    print (dataframe.shape)
    
    norm = MinMaxScaler().fit_transform(dataframe)
    '''
        Nova Dataframe para guardar o numero do cluster a que pertende cada entidade
        Dataframe to tipo [#entidades, #algoritmos]  
    '''
    new_df = pd.DataFrame(columns=['cluster_kmeans','cluster_dbscan','cluster_agglomerative'], index=dataframe.index[:len(norm)])
    '''
        Definição do parametro k (# clusters) para o KMeans e AgglomerativeClustering
        Condição para alterar o parametro k, caso o numero de entidades seja inferior ao parametro
        como escolher o K? - metodo de elbow
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
        Cria objeto Kmeans e calcula os clusters com os dados normalizados
    '''
    kmeans = KMeans(n_clusters=n_clusters4kmeans).fit(norm).predict(norm)
    print('kmeans - ', time.time()-tempo)
    tempo= time.time()


    '''
    chama a funçãoo para heatmap do kmeans
    '''
    auxheat = pd.DataFrame(data=norm, columns=dataframe.columns, index=dataframe.index)
    auxheat['clusters'] = kmeans
    X = heat('KMEANS',auxheat, file, day, window)   #heatmap
    '''
        Cria objeto DBSCAN e calcula os clusters com os dados normalizados,
        Do método DBSCAN:
            - eps -> parametro que indica a distancia maxima considerada entre dois pontos considerados na vizinhança de cada um;
            - min_smaples -> numero mínimo de amostras para considerar um cluster;
            - n_jobs -> numero de trabalhos em paralelo.
    '''
    dbscan = DBSCAN(eps=epsilon, min_samples=2, n_jobs=-1).fit_predict(norm)
    print('dbscan - ', time.time()-tempo)
    tempo= time.time()
    '''
        Cria objeto AgglomerativeClustering e calcula os clusters com os dados normalizados
    '''
    agglometative = AgglomerativeClustering(n_clusters=n_clusters4kmeans).fit_predict(norm)
    print('agglometative - ', time.time()-tempo)
    tempo= time.time()
    '''
        Guarda a informacao sobre os clusters de cada entidade dataframe
    '''
    new_df['cluster_kmeans'] = kmeans
    new_df['cluster_dbscan'] = dbscan
    new_df['cluster_agglomerative'] = agglometative

    '''
        Limpa as variáveis dos algoritmos (só com o gc.collect())
    '''
    del dbscan, kmeans, norm,  agglometative
    gc.collect()
    print('donne clustering')
    ''' 
        Retorma da dataframe com a informacao dos clusters
    '''
    return new_df

'''
    Funcao para analise dos resultados, aplica metricas (True Positives, False Positives, True Negatives, False Negatives),

'''
def result_analysis(df, file, windows, view, day, df_features):
    del df.index.name
    '''
        Usa variaveis globais, no caso das variaveis:
            - victims, attackers -> recolhe informacao de acordo com o dia
            - score_victims, score_attackers -> variaveis usadas para armazenar a cada janela de tempo os scores das diferentes entidades
            - save_clusters_victim, save_clusters_attacker, list_all_windows, list_all_windows_attacker -> variáveis que compilam a informação de todas as janelas de tempo num unico ficheiro
    '''
    global victims, attackers
    global score_victims, score_attackers
    global save_clusters_victim, save_clusters_attacker, list_all_windows, list_all_windows_attacker
    '''
        Caminho para armazenar os resultados
    '''
    file_prefix = 'day'+str(day)+'/'+str(windows)+'min/results_dynamic/'+str(view)+'_'+str(file).split('.')[0].split('/')[-1]
    
    '''
        Procura a existencia de vitimas e atacantes de acordo com o dia a ser processado
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
        Caso sejam encontradas(os) vitimas e/ou atacantes,
    '''
    if (save_clusters_victim==True) or (save_clusters_attacker==True):
        print('saving files')
        '''
            Guarda a informacao sobre os clusters em ficheiros separados e identificados pela janela de tempo e algoritmo
        '''
        df['cluster_kmeans'].to_csv(file_prefix + '_kmeans.csv', header=True)
        df['cluster_dbscan'].to_csv(file_prefix +'_dbscan.csv', header=True)
        df['cluster_agglomerative'].to_csv(file_prefix+'_agglomerative.csv', header=True)
        '''
            Escolher cluster de outliers do dbscan
        '''
        lof_clusters = df[df['cluster_dbscan'].values == -1]
        lof_clusters = lof_clusters['cluster_dbscan']
        '''
            Guarda o numero total de entidades por cada cluster para os diferentes algoritmos
        '''
        ncluster_kmeans = df.groupby('cluster_kmeans')['cluster_dbscan'].count().to_frame() #.to_csv(file_prefix+'_NCLUSTER_kmeans.csv', header=True)
        ncluster_dbscan = df.groupby('cluster_dbscan')['cluster_kmeans'].count().to_frame() #.to_csv(file_prefix+'_NCLUSTER_dbscan.csv', header=True)
        # ncluster_hdbscan = df.groupby('cluster_hdbscan')['cluster_kmeans'].count().to_frame() #.to_csv(file_prefix+'_NCLUSTER_hdbscan.csv', header=True)
        ncluster_agglomerative = df.groupby('cluster_agglomerative')['cluster_kmeans'].count().to_frame() #.to_csv(file_prefix+'_NCLUSTER_aglomerative.csv', header=True)
        '''
            Selecionar os cluster com numero de entidades igual ou menor a 15 e para os algoritmos baseados em densidade considera o cluster de outliers (cluster '-1')
        '''
        ncluster_kmeans_ = ncluster_kmeans[ncluster_kmeans.values <= 1]
        ncluster_dbscan_ = ncluster_dbscan[ncluster_dbscan.values <= 1]
        if '-1' not in str(ncluster_dbscan_.index) and ncluster_dbscan.index.values.min()<0:
            ncluster_dbscan_.at['100'] = (ncluster_dbscan[ncluster_dbscan.index < 0].values[0])
        ncluster_agglomerative_ = ncluster_agglomerative[ncluster_agglomerative.values <= 1]

        cluster_results_victim = pd.DataFrame()

        '''
            Analise de Vitimas
        '''
        for victim in victims[str(day)]:
            '''
                Guardar para cada algoritmo, o numero e tamanho do cluster em que estão as vitimas 
            '''
            if victim in df.index:
                cluster_results_victim.at[victim,'cluster_kmeans'] = int(df.loc[victim,'cluster_kmeans'])
                cluster_results_victim.at[victim,'cluster_kmeans_size'] = int(ncluster_kmeans.loc[df.loc[victim,'cluster_kmeans']][0])
                cluster_results_victim.at[victim,'cluster_dbscan'] = int(df.loc[victim,'cluster_dbscan'])
                cluster_results_victim.at[victim,'cluster_dbscan_size'] = int(ncluster_dbscan.loc[df.loc[victim,'cluster_dbscan']][0])
                cluster_results_victim.at[victim,'cluster_agglomerative'] = int(df.loc[victim,'cluster_agglomerative'])
                cluster_results_victim.at[victim,'cluster_agglomerative_size'] = int(ncluster_agglomerative.loc[df.loc[victim,'cluster_agglomerative']][0])
        '''
            Retira o numero dos clusters em que estao as vitimas, para ussar como indice nas dataframes 'victims_kmeans', 'victims_dbscan', 'victims_aglomerative' 
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
                Dataframe para guardar os resultados com as metricas definidas abaixo
            '''
            scores = pd.DataFrame(columns=['kmeans','dbscan','agglomerative'])

            for victim in victims[str(day)]:
                '''
                    Filtra os clusters com 1 entidade (para i agglomerative e kmeans) e o cluster outlier (dbscan)
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
                Numero de vitimas detetadas por algoritmo
            '''
            scores['kmeans'] = victims_kmeans['victims_kmeans']
            scores['dbscan'] = victims_dbscan['victims_dbscan']
            scores['agglomerative'] = victims_agglomerative['victims_agglomerative']
            scores.at['tot_kmeans'] = scores.iloc[:len(victims_kmeans.index)]['kmeans'].sum()
            scores.at['tot_dbscan'] = scores.iloc[:len(victims_dbscan.index)]['dbscan'].sum()
            scores.at['tot_agglomerative'] = scores.iloc[:len(victims_agglomerative.index)]['agglomerative'].sum()
            scores.fillna(value=0, inplace=True)
            
            '''
                Percorre os algritmos e conta o numero de entidades e vitimas por cluster
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
                    Aplica as metricas:
                    -    True Positices (TP) -  entidades corretamente classificadas como outliers;
                    -    False Positives (FP) - entidades erradamente classificadas como outliers
                    -    True Negatives (TN) - entidades corretamente classificadas como 'normais';
                    -    False Negatives (FN) - entidades erradamente classificadas como 'normais';
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
                    Condição para evitar divisoes por zero
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
                Aplicar LOF ao cluster de outliers identificado pelo numero '100'
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
                O score do LOF é negativo, quanto mais negativo maior a probabilidade de ser um outlier...
                entao o min() corresponde a entidade identificada com maior probabilidade de ser outlier...
            '''
            scores.at['Max_score'] = [0,lof_scores.min().values,0] # porque os resultados são negativos
            '''
                Para cada vitima retira o score LOF,
                Na analise compara-se o MAX_SCORE com os scores de cada vítima
            '''
            for victim in victims[str(day)]:
                if victim in lof_scores.index:
                    scores.at[str(victim)] = lof_scores.loc[str(victim)].values
            scores.at['Time'] = 1111
            score_victims.append(scores)

        '''
            Análise de atacantes
        '''
        cluster_results_attacker = pd.DataFrame()

        for attacker in attackers[str(day)]:
            '''
                Guardar para cada algoritmo, o numero e tamanho do cluster em que estão os atacantes 
            '''
            if attacker in df.index:
                cluster_results_attacker.at[attacker,'cluster_kmeans'] = int(df.loc[attacker,'cluster_kmeans'])
                cluster_results_attacker.at[attacker,'cluster_kmeans_size'] = int(ncluster_kmeans.loc[df.loc[attacker,'cluster_kmeans']][0])
                cluster_results_attacker.at[attacker,'cluster_dbscan'] = int(df.loc[attacker,'cluster_dbscan'])
                cluster_results_attacker.at[attacker,'cluster_dbscan_size'] = int(ncluster_dbscan.loc[df.loc[attacker,'cluster_dbscan']][0])
                cluster_results_attacker.at[attacker,'cluster_agglomerative'] = int(df.loc[attacker,'cluster_agglomerative'])
                cluster_results_attacker.at[attacker,'cluster_agglomerative_size'] = int(ncluster_agglomerative.loc[df.loc[attacker,'cluster_agglomerative']][0])
        '''
            Retira o numero dos clusters em que estao os atacantes, para ussar como indice nas dataframes 'attackers_kmeans', 'attackers_dbscan', 'attackers_aglomerative' 
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
                Dataframe para guardar os resultados com as metricas definidas abaixo
            '''
            scores = pd.DataFrame(index=set(index_count_attacker), columns=['kmeans','dbscan','agglomerative'])
            true_negatives, false_negatives=[],[]
            for attacker in attackers[str(day)]:
                '''
                    Filtra os clusters com 1 entidade (oara i agglomerative e kmeans) e o cluster outlier (dbscan)
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
            # attackers_hdbscan['window'] = timeWindow
            # attackers_hdbscan.fillna(value=0, inplace=True)
            attackers_dbscan['window'] = 1111
            attackers_dbscan.fillna(value=0, inplace=True)
            attackers_kmeans['window'] = 1111
            attackers_kmeans.fillna(value=0, inplace=True)
            '''
                Numero de atacantes detetados por algoritmo
            '''
            scores['kmeans'] = attackers_kmeans['attackers_kmeans']
            scores['dbscan'] = attackers_dbscan['attackers_dbscan']
            # scores['hdbscan'] = attackers_hdbscan['attackers_hdbscan']
            scores['agglomerative'] = attackers_agglomerative['attackers_agglomerative']
            scores.at['tot_kmeans'] = scores.iloc[:len(attackers_kmeans.index)]['kmeans'].sum()
            scores.at['tot_dbscan'] = scores.iloc[:len(attackers_dbscan.index)]['dbscan'].sum()
            # scores.at['tot_hdbscan'] = scores.iloc[:len(attackers_hdbscan.index)]['hdbscan'].sum()
            scores.at['tot_agglomerative'] = scores.iloc[:len(attackers_agglomerative.index)]['agglomerative'].sum()
            scores.fillna(value=0, inplace=True)
            '''
                Percorre os algritmos e conta o numero de entidades e atacantes por cluster
            '''
            for algorithm in scores.columns:
                if str(algorithm) == 'kmeans':
                    ncluster = ncluster_kmeans_.values.sum()
                    count_attacker = attackers_kmeans['attackers_kmeans']
                elif str(algorithm) == 'dbscan':
                    ncluster = ncluster_dbscan_.values.sum()
                    count_attacker = attackers_dbscan['attackers_dbscan']
                # elif str(algorithm) == 'hdbscan':
                #     ncluster = ncluster_hdbscan_.values.sum()
                #     count_attacker = attackers_hdbscan['attackers_hdbscan']
                elif str(algorithm) == 'agglomerative':
                    ncluster = ncluster_agglomerative_.values.sum()
                    count_attacker = attackers_agglomerative['attackers_agglomerative']
                print(str(algorithm) + ' :')
                print(ncluster)
                '''
                    Aplica as metricas:
                    -    True Positices (TP) -  entidades corretamente classificadas como outliers;
                    -    False Positives (FP) - entidades erradamente classificadas como outliers
                    -    True Negatives (TN) - entidades corretamente classificadas como 'normais';
                    -    False Negatives (FN) - entidades erradamente classificadas como 'normais';
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
                    Condição para evitar divisoes por zero
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
                Aplicar LOF ao cluster de outliers identificado pelo numero '100'
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
                O score do LOF é negativo, quanto mais negativo maior a probabilidade de ser um outlier...
                entao o min() corresponde a entidade identificada com maior probabilidade de ser outlier...
            '''
            scores.at['Max_score'] = [0,lof_scores.min().values,0]
            '''
                Para cada atacante retira o score LOF,
                Na analise compara-se o MAX_SCORE com os scores de cada atacante
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
        Ficheiros csv com as features
    '''
    files_features = sys.argv[3:]
    '''
        janela de tempo a analiar
    '''
    day = int(sys.argv[1])
    window = int(sys.argv[2])
    for file in files_features:
        tempo =time.time()
        df_timestamp = []
        '''
            Carrega o ficheiro por 'partes/chunk' para uma dataframe
        '''
        for chunk in pd.read_csv(file, sep=',', dtype='object', chunksize=100000):
            df_timestamp.append(chunk)

        df_timestamp = pd.concat(df_timestamp)
        
        #print(df_timestamp.head(5))
        print("Donne reading csv")
        #print(time.time()-tempo)
        df_timestamp.set_index(df_timestamp.iloc[:,0], inplace=True)
        df_timestamp.drop(['Unnamed: 0'], axis=1 , inplace=True)
        del df_timestamp.index.name
        # Aplicar algoritmos de clustering
        if len(df_timestamp.index) > 0:
            src_df, dst_df = [],[]
            for ind in df_timestamp.index:
                if '172.31.' in str(ind):
                    src_df.append(ind)
                else:
                    dst_df.append(ind)
            src_df = df_timestamp.loc[src_df]
            dst_df = df_timestamp.loc[dst_df]
            # i = datetime.strptime(str(i),"%Y-%m-%d %H:%M:%S")
            # i = i.timestamp()-(4*60*60)
            # i = datetime.fromtimestamp(i)
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
            # reset nos indices para poder guardar no formato .feather
            # Tot.reset_index(inplace=True)
            # # Guardar os features extraidas 
            # Tot.to_csv('day'+str(day)+'/'+str(window)+'min/'+str(window)+'_features_'+str(day)+'_'+str(k)+'.csv')
        else:
            print("Time stamp not found")
        '''
        Guarda em ficheiros CSV os resultados;
        As pastas para cada dia, janela de tempo, e abordagem devem ser criadas antes de excutar o script
        Na pasta: exemplo para dia 2 - ../dia2/10min/results_dynamic/..._scores_victims_new.csv
        '''
    if len(score_victims) > 0:
        pd.concat(score_victims).to_csv('day'+str(day)+'/'+str(window)+'min/results_dynamic/'+str(file).split('.')[0].split('/')[-1]+'_scores_victims_new.csv', header=True)
    if len(score_attackers) > 0:
        pd.concat(score_attackers).to_csv('day'+str(day)+'/'+str(window)+'min/results_dynamic/'+str(file).split('.')[0].split('/')[-1]+'_scores_attackers_new.csv', header=True)
    print(str(file) + ' extracted')

if __name__ == '__main__':
    main()
