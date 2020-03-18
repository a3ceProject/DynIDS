'''
    Script para aplicar clustering com as features dinamicas;
    Como usar:  pyhton3 feature_extractor.py <janela de tempo> <caminho para ficheiro com flows>
    Exemplo: time python3 feature_extractor.py old_wednesday_16_02_18.csv
'''
import sys
import time
import pandas as pd
import numpy
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering, ward_tree
from sklearn.preprocessing import MinMaxScaler
#import hdbscan as hd
from pathlib import Path #valente2
import os #valente2
import gc
import joblib
from datetime import datetime
columns_com_prefixo = [] #valente_2

'''
    Funcao para extrair do nome do ficheiro o respetivo dia
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
    Funcao para restringir as janelas de tempo ao respetivo dia,
    porque existem eventos com datas aneriores ao dia em análise.
'''
def date(day):
    start_date = 0
    end_date = 0
    if day==1:
        # WEDNESDAY 14-02-2018
        start_date = datetime(2018,2,14,0,0,0)
        end_date = datetime(2018,2,15,0,0,0)
    if day==2:
        # THURSDAY 15-02-2018  machine1
        start_date = datetime(2018,2,15,0,0,0)
        end_date = datetime(2018,2,16,0,0,0)
    if day==3:
        # FRIDAY 16-02-2018    Dia com problemas... muito lento
        start_date = datetime(2018,2,16,0,0,0)
        end_date = datetime(2018,2,17,0,0,0)    
    if day==4:
        # TUESDAY 20-02-2018 machine3
        start_date = datetime(2018,2,20,0,0,0)
        end_date = datetime(2018,2,21,0,0,0)
    if day==5:  # leva muito tempo
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

# Função para extração dos portos a ser considerados features
def get_ports(df): # SrcPortContacted, SrcPortUsed, DstPortContacted, DstPortUsed, mode_ports):
    #list_ports = [21,22,23,25,53,67,68,80,123,135,137,138,139,194,443,445,500,1900,1920,2181,2816,3128,3389,5355,6188,6667,7112,8080,8443,10397,27017,30303,50010]  #LD
    #list_ports_reia = [80, 194, 25, 22]   #LD
    #portos_ataques_especificos = [21]   #LD
    most_used_ports_dst = df['Dst Port'].value_counts()
    most_used_ports = most_used_ports_dst
    most_used_ports_src = df['Src Port'].value_counts()
    most_used_ports = most_used_ports_dst.append(most_used_ports_src) #
    portosSrc_pref = [] #valente_2
    portosDst_pref = [] #valente_2
    list_ports = []
    portosSrc = []
    portosDst = []       
    method = 3  # mothod == 1 Outgene;  method == 2 5050; method == 3  top,uncommon,min  ; method == 4 teste
    num_portos = 100
    global columns_com_prefixo #valente_2
    columns_com_prefixo = []
    if method == 1:
    	list_ports = [80, 194, 25, 22]
    	print ("Outgene ports selected ______________________________")
    
    if method == 2:
    	#most_used_ports_src = df['Src Port'].value_counts()
    	#most_used_ports = most_used_ports_dst.append(most_used_ports_src) #LD
    	for i in most_used_ports.sort_values(ascending=False).keys():   
    		if len(list_ports)<=num_portos/2:  #LD  num_portos 							#detects top talkers
    			if i not in list_ports:
    				if i < 49151:      #LD  < 49151  65535    and i!=8080 and i!=53 
    					list_ports.append(i) 
    					print (i)
    	print ("Above is TOP Count ports selected ______________________________")
    	for i in most_used_ports.sort_values(ascending=True).keys():      
    		if len(list_ports)<=num_portos: #LD   *2 num_portos*2
    			if i not in list_ports:
    				if i < 49151: #LD    1024 or i==3389		# detects port-scans   - find unique ports, only used once, in well known ports range.
    					list_ports.append(i)
    					print (i)
    	print ("Above is MIN count ports selected ______________________________")
   
    if method == 3:
        df.reset_index(inplace=True)
        aux = df.groupby(['Dst Port']).nunique()
        aux.index.name = None
        uniqueport = aux.sort_values(by=['Src IP'],ascending=False)
        uniqueports= uniqueport[uniqueport['Src IP']<10].index.tolist() #uniqueports is a list of ports contacted by less the 10 IPs por ordem decrescente de contactos

        for i in most_used_ports.sort_values(ascending=False).keys():   
            if len(list_ports) <= num_portos/3:  #LD  num_portos 							#detects top talkers
                if i not in list_ports:
                    if i < 49151:      #LD  < 49151  65535    and i!=8080 and i!=53 
                        list_ports.append(i) 
                        #print(len(list_ports))
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('T'+j+'SrcTo') #Valente #valente_2
                        portosSrc_pref.append('T'+j+'SrcFrom') #Valente# #valente_2
                        portosDst_pref.append('T'+j+'DstTo') #Valente #valente_2
                        portosDst_pref.append('T'+j+'DstFrom') #Valente #valente_2
                        #portos sem prefixo
                        portosSrc.append(j+'SrcTo') #Valente #valente_2
                        portosSrc.append(j+'SrcFrom') #Valente# #valente_2
                        portosDst.append(j+'DstTo') #Valente #valente_2
                        portosDst.append(j+'DstFrom') #Valente #valente_2
            if len(list_ports) <=  2*num_portos/3: #LD   *2 num_portos*2 					#dectects uncomon ports - find highest talkers within uncomon ports
                if i not in list_ports and i in uniqueports:
                    if i < 49151:
                        list_ports.append(i)
                        #print(len(list_ports))
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('U'+j+'SrcTo') #Valente #valente_2
                        portosSrc_pref.append('U'+j+'SrcFrom') #Valente# #valente_2
                        portosDst_pref.append('U'+j+'DstTo') #Valente #valente_2
                        portosDst_pref.append('U'+j+'DstFrom') #Valente #valente_2
                        #portos sem prefixo
                        portosSrc.append(j+'SrcTo') #Valente #valente_2
                        portosSrc.append(j+'SrcFrom') #Valente# #valente_2
                        portosDst.append(j+'DstTo') #Valente #valente_2
                        portosDst.append(j+'DstFrom') #Valente #valente_2
        print ("Above is TOP Count ports selected ______________________________")
        print ("Above is unique contacted port selected ______________________________")

        for i in most_used_ports.sort_values(ascending=True).keys():      
            if len(list_ports) <= num_portos: #LD   *2 num_portos*2
                if i not in list_ports:
                    if i <  1024 or i==3389:		#detects port-scans   - find unique ports, only used once, in well known ports range.
                        list_ports.append(i)
                        #print(len(list_ports))
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('M'+j+'SrcTo') #Valente #valente_2
                        portosSrc_pref.append('M'+j+'SrcFrom') #Valente# #valente_2
                        portosDst_pref.append('M'+j+'DstTo') #Valente #valente_2
                        portosDst_pref.append('M'+j+'DstFrom') #Valente #valente_2
                        # portos em prefixo
                        portosSrc.append(j+'SrcTo') #Valente #valente_2
                        portosSrc.append(j+'SrcFrom') #Valente# #valente_2
                        portosDst.append(j+'DstTo') #Valente #valente_2
                        portosDst.append(j+'DstFrom') #Valente #valente_2
        print ("Above is MIN count ports selected ______________________________")
        columns_com_prefixo+=(portosSrc_pref+portosDst_pref)
   
    if method == 4:
        for i in most_used_ports.sort_values(ascending=False).keys():
            if len(list_ports)<=num_portos:  #LD  num_portos                                                      #det$
                if i not in list_ports:
                    if i < 49151:      #LD  < 49151  65535    and i!=8080 and i!=53
                        list_ports.append(i)
                        print (i)
        print ("Above is TOP Count ports selected ______________________________")
    
    if method != 3:
        for j in list_ports:
            j = str(j)
            portosSrc.append(j+'SrcTo') #Valente
            portosSrc.append(j+'SrcFrom') #Valente#
            portosDst.append(j+'DstTo') #Valente
            portosDst.append(j+'DstFrom') #Valente
    return portosSrc, portosDst



# função para extrair os valores de cada feature relacionada com os portos do ponto de vista da Source
def get_src_pkts(df, list_ports):
    df = df.groupby('Src IP')
    new_df = pd.DataFrame(0,index=df.groups, columns=list_ports)
    for i in df.groups:
        if isinstance(df.get_group(i)['Src Port'].values, numpy.ndarray):
            k=0
            for port in df.get_group(i)['Src Port'].values:
                if (str(port)+'SrcTo') in new_df.columns:
                    new_df.at[i, str(port)+'SrcTo'] += df.get_group(i)['Tot Fwd Pkts'].values[k]+1
                k+=1
        elif (str(df.get_group(i)['Src Port'].values)+'SrcTo') in new_df.columns:
            new_df.at[i, str(port)+'SrcTo'] += df.get_group(i)['Tot Fwd Pkts'].values+1
        if isinstance(df.get_group(i)['Dst Port'].values, numpy.ndarray):
            k=0
            for port in df.get_group(i)['Dst Port'].values:
                if (str(port)+'SrcFrom') in new_df.columns:
                    new_df.at[i, str(port)+'SrcFrom'] += df.get_group(i)['Tot Bwd Pkts'].values[k]-1
                k+=1
        elif (str(df.get_group(i)['Dst Port'].values)+'SrcFrom') in new_df.columns:
            new_df.at[i, str(port)+'SrcFrom'] += df.get_group(i)['Tot Bwd Pkts'].values-1
    new_df = new_df.loc[:, (new_df != 0).any(axis=0)]
    return new_df

# função para extrair os valores de cada feature relacionada com os portos do ponto de vista da Destination
def get_dst_pkts(df, list_ports):
    #df.set_index('Dst IP')
    df = df.groupby('Dst IP')
    new_df = pd.DataFrame(0, index=df.groups, columns=list_ports)
    for i in df.groups:
        if isinstance(df.get_group(i)['Dst Port'].values, numpy.ndarray):
            k=0
            for port in df.get_group(i)['Dst Port'].values:
                if (str(port)+'DstTo') in new_df.columns:
                    new_df.at[i, str(port)+'DstTo'] += df.get_group(i)['Tot Bwd Pkts'].values[k]-1
                k+=1
        elif (str(df.get_group(i)['Dst Port'].values)+'DstTo') in new_df.columns:
            new_df.at[i, str(port)+'DstTo'] += df.get_group(i)['Tot Bwd Pkts'].values-1
        # else:
        #     new_df.at[i, str(port)+'DstTo'] =  new_df.loc[i, str(port)+'DstTo'] + df.get_group(i)['Tot Bwd Pkts'].values-1

        if isinstance(df.get_group(i)['Src Port'].values, numpy.ndarray):
            k=0
            for port in df.get_group(i)['Src Port'].values:
                if (str(port)+'DstFrom') in new_df.columns:
                    new_df.at[i, str(port)+'DstFrom'] += df.get_group(i)['Tot Fwd Pkts'].values[k]+1
                # else:
                #     new_df.at[i, str(port)+'DstFrom'] += df.get_group(i)['Tot Fwd Pkts'].values[k]+1
                k+=1
        elif(str(df.get_group(i)['Src Port'].values)+'DstFrom') not in new_df.columns:
            new_df.at[i, str(port)+'DstFrom'] += df.get_group(i)['Tot Fwd Pkts'].values+1
    new_df = new_df.loc[:, (new_df != 0).any(axis=0)]
    return new_df


def replace_columns(old_columns): #valente_2
    global columns_com_prefixo
    if len(columns_com_prefixo) == 0:
        return old_columns
    print (old_columns)
    prefix_columns_partial = []
    for col_simple in old_columns:
        for col_prefix in columns_com_prefixo:
            if (str(col_prefix).find(col_simple) != -1) and len(col_prefix)==(len(col_simple)+1):
                #print('Coluna simples - ', col_simple)
                #print('Coluna prefixo - ', col_prefix)
                prefix_columns_partial.append(col_prefix)
    print (prefix_columns_partial)
    return prefix_columns_partial


def main():
    files = sys.argv[1:]
    dir_path = os.path.dirname(os.path.realpath(__file__)) #valente2
    for file in files:
        tempo =time.time()
        df_timestamp = []
        for chunk in pd.read_csv(file, sep=',', dtype='object', chunksize=100000):
            df_timestamp.append(chunk)
        df_timestamp = pd.concat(df_timestamp)
        #print(df_timestamp.head(5))
        print("Donne reading csv")
        print(time.time()-tempo)
        # preencher campos a NaN
        df_timestamp = df_timestamp.fillna(0)
        # remover as linhas de cabeçalho duplicado
        df_timestamp = df_timestamp[df_timestamp['Src Port'].map(lambda x: str(x)!="Src Port")]
        # remover linhas sem timestamp
        df_timestamp = df_timestamp[df_timestamp['Timestamp'].map(lambda x: str(x)!='0')]
        # converter os tipos de dados
        df_timestamp['Src Port'] = df_timestamp['Src Port'].astype('int64')
        df_timestamp['Dst Port'] = df_timestamp['Dst Port'].astype('int64')
        df_timestamp['Tot Fwd Pkts'] = df_timestamp['Tot Fwd Pkts'].astype('int64')
        df_timestamp['Tot Bwd Pkts'] = df_timestamp['Tot Bwd Pkts'].astype('int64')
        df_timestamp['TotLen Fwd Pkts'] = df_timestamp['TotLen Fwd Pkts'].astype('float64')
        df_timestamp['TotLen Bwd Pkts'] = df_timestamp['TotLen Bwd Pkts'].astype('float64')

        timestamp = df_timestamp['Timestamp'].tolist()
        timestamp = pd.to_datetime(timestamp, format="%d/%m/%Y %I:%M:%S %p")
        df_timestamp['Timestamp'] = timestamp
        # del timestamp

        print("time converted")
        k,m=0,0
        day = get_day(file)
        start_date, end_date = date(day)
        for timeWindows in [10,60,240,480,1440]: #valente 
            # saved_groups = open('groups_'+str(timeWindows)+'_'+file.split('/')[-1]+'.txt','w') #valente
            grouped = df_timestamp.groupby(by=pd.Grouper(key='Timestamp', freq=str(timeWindows*60)+'s'))
            for i in grouped.indices.keys(): #valente
                if (i-start_date).total_seconds()>=0 and (i-end_date).total_seconds()<=86400:
                    print(str(i))
                # Estas datas tem +4 horas porque lêm os ficheiros originados pelo CICFlowMeter
                # Se os dados forem lidos dos ficheiros ...features(..).csv tem de se reduzir 4h nestas datas, 
                # para os scripts pandas_FlowReia e pandas_FlowReduced não precisa.
                # if str(i) in [
                #         '2018-02-14 04:00:00', # 24H
                #         '2018-02-14 12:00:00','2018-02-14 16:00:00',# 4H
                #         '2018-02-14 14:00:00','2018-02-14 15:00:00','2018-02-14 16:00:00','2018-02-14 17:00:00','2018-02-14 18:00:00','2018-02-14 19:00:00','2018-02-14 20:00:00', #2H, 1H
                #         '2018-02-14 14:20:00','2018-02-14 14:30:00','2018-02-14 14:40:00','2018-02-14 14:50:00','2018-02-14 15:10:00','2018-02-14 15:20:00', '2018-02-14 15:30:00', # 30min, 10min
                #         '2018-02-14 15:40:00','2018-02-14 15:50:00','2018-02-14 16:10:00','2018-02-14 18:10:00','2018-02-14 18:20:00','2018-02-14 18:30:00','2018-02-14 18:40:00',
                #         '2018-02-14 18:50:00','2018-02-14 19:10:00','2018-02-14 19:20:00','2018-02-14 19:30:00','2018-02-14 19:40:00','2018-02-14 19:50:00',
                #         #Dia 15
                #         '2018-02-15 04:00:00', # 24H
                #         '2018-02-15 12:00:00', # 4H
                #         '2018-02-15 13:00:00','2018-02-15 14:00:00','2018-02-15 15:00:00','2018-02-15 16:00:00','2018-02-15 17:00:00', # 2H, 1H
                #         '2018-02-15 13:10:00','2018-02-15 13:20:00','2018-02-15 13:30:00','2018-02-15 13:40:00','2018-02-15 13:50:00','2018-02-15 14:10:00','2018-02-15 14:20:00', # 30min, 10min
                #         '2018-02-15 14:30:00','2018-02-15 14:40:00','2018-02-15 14:50:00','2018-02-15 15:10:00','2018-02-15 15:20:00','2018-02-15 15:30:00','2018-02-15 15:40:00',
                #         '2018-02-15 15:50:00','2018-02-15 16:10:00','2018-02-15 12:20:00', #LD apagar ultimo 12:20
                #          #Dia 16
                #         '2018-02-16 04:00:00', # 24H
                #         '2018-02-16 12:00:00','2018-02-16 16:00:00', # 4H
                #         '2018-02-16 14:00:00','2018-02-16 15:00:00','2018-02-16 16:00:00','2018-02-16 17:00:00','2018-02-16 18:00:00','2018-02-16 19:00:00', # 2H, 1H
                #         '2018-02-16 14:10:00','2018-02-16 14:20:00','2018-02-16 14:30:00','2018-02-16 14:40:00','2018-02-16 14:50:00','2018-02-16 15:10:00','2018-02-16 15:20:00', # 30min, 10min
                #         '2018-02-16 15:30:00','2018-02-16 15:40:00','2018-02-16 15:50:00','2018-02-16 16:10:00','2018-02-16 16:20:00','2018-02-16 17:30:00','2018-02-16 17:40:00',
                #         '2018-02-16 17:50:00','2018-02-16 18:10:00','2018-02-16 18:20:00','2018-02-16 18:30:00','2018-02-16 18:40:00','2018-02-16 18:50:00',
                #         #Dia 20
                #         '2018-02-20 04:00:00', # 24H
                #         '2018-02-20 12:00:00','2018-02-20 16:00:00', # 4H
                #         '2018-02-20 13:00:00','2018-02-20 14:00:00','2018-02-20 15:00:00','2018-02-20 16:00:00','2018-02-20 17:00:00','2018-02-20 18:00:00', # 2H, 1H
                #         '2018-02-20 14:10:00','2018-02-20 14:20:00','2018-02-20 14:30:00','2018-02-20 14:40:00','2018-02-20 14:50:00','2018-02-20 15:10:00','2018-02-20 15:20:00', # 30min, 10min
                #         '2018-02-20 15:30:00','2018-02-20 17:10:00','2018-02-20 17:20:00','2018-02-20 17:30:00','2018-02-20 17:40:00','2018-02-20 17:50:00',
                #         #Dia 21
                #         '2018-02-21 04:00:00', # 24H
                #         '2018-02-21 12:00:00','2018-02-21 16:00:00', # 4H
                #         '2018-02-21 13:00:00','2018-02-21 14:00:00','2018-02-21 15:00:00','2018-02-21 16:00:00','2018-02-21 17:00:00','2018-02-21 18:00:00','2018-02-21 19:00:00', # 2H, 1H
                #         '2018-02-21 14:10:00','2018-02-21 14:20:00','2018-02-21 14:30:00','2018-02-21 14:40:00','2018-02-21 14:50:00','2018-02-21 18:10:00','2018-02-21 18:20:00', # 30min, 10min
                #         '2018-02-21 18:30:00','2018-02-21 18:40:00','2018-02-21 18:50:00','2018-02-21 19:10:00','2018-02-21 19:20:00','2018-02-21 19:30:00',
                #         #Dia 22
                #         '2018-02-22 12:00:00','2018-02-22 16:00:00', # 4H
                #         '2018-02-22 13:00:00','2018-02-22 14:00:00','2018-02-22 15:00:00','2018-02-22 16:00:00','2018-02-22 17:00:00','2018-02-22 18:00:00','2018-02-22 19:00:00', # 2H, 1H
                #         '2018-02-22 20:00:00','2018-02-22 21:00:00',
                #         '2018-02-22 14:10:00','2018-02-22 14:20:00','2018-02-22 14:30:00','2018-02-22 14:40:00','2018-02-22 14:50:00','2018-02-22 15:10:00','2018-02-22 15:20:00', # 30min, 10min
                #         '2018-02-22 15:30:00','2018-02-22 17:40:00','2018-02-22 17:50:00','2018-02-22 18:10:00','2018-02-22 18:20:00','2018-02-22 18:30:00','2018-02-22 18:40:00',
                #         '2018-02-22 18:50:00','2018-02-22 20:10:00','2018-02-22 20:20:00','2018-02-22 20:30:00','2018-02-22 20:40:00','2018-02-22 20:50:00',
                #         #Dia 23
                #         '2018-02-23 04:00:00', # 24H
                #         '2018-02-23 13:00:00','2018-02-23 14:00:00','2018-02-23 15:00:00','2018-02-23 16:00:00','2018-02-23 17:00:00','2018-02-23 18:00:00','2018-02-23 19:00:00', # 2H, 1H
                #         '2018-02-23 20:00:00',
                #         '2018-02-23 13:50:00','2018-02-23 14:10:00','2018-02-23 14:20:00','2018-02-23 14:30:00','2018-02-23 14:40:00','2018-02-23 14:50:00','2018-02-23 15:10:00', # 30min, 10min
                #         '2018-02-23 15:20:00','2018-02-23 16:50:00','2018-02-23 17:10:00','2018-02-23 17:20:00','2018-02-23 17:30:00','2018-02-23 17:40:00','2018-02-23 17:50:00',
                #         '2018-02-23 18:10:00','2018-02-23 18:20:00','2018-02-23 18:30:00','2018-02-23 19:10:00','2018-02-23 19:20:00','2018-02-23 19:30:00','2018-02-23 19:40:00',
                #         #Dia 28
                #         '2018-02-28 04:00:00', # 24H
                #         '2018-02-28 12:00:00','2018-02-28 16:00:00', # 4H
                #         '2018-02-28 13:00:00','2018-02-28 14:00:00','2018-02-28 15:00:00','2018-02-28 16:00:00','2018-02-28 17:00:00','2018-02-28 18:00:00','2018-02-28 19:00:00', # 2H, 1H
                #         '2018-02-28 14:40:00','2018-02-28 14:50:00','2018-02-28 15:10:00','2018-02-28 15:20:00','2018-02-28 15:30:00','2018-02-28 15:40:00','2018-02-28 15:50:00', # 30min, 10min
                #         '2018-02-28 16:10:00','2018-02-28 16:20:00','2018-02-28 17:30:00','2018-02-28 17:40:00','2018-02-28 17:50:00','2018-02-28 18:10:00','2018-02-28 18:20:00',
                #         '2018-02-28 18:30:00','2018-02-28 18:40:00','2018-02-28 18:50:00','2018-02-28 19:10:00',
                #         #Dia 01
                #         '2018-03-01 04:00:00', # 24H
                #         '2018-03-01 12:00:00','2018-03-01 16:00:00', # 4H
                #         '2018-03-01 13:00:00','2018-03-01 14:00:00','2018-03-01 15:00:00','2018-03-01 16:00:00','2018-03-01 17:00:00','2018-03-01 18:00:00','2018-03-01 19:00:00', # 2H, 1H
                #         '2018-03-01 20:00:00',
                #         '2018-03-01 13:40:00','2018-03-01 13:50:00','2018-03-01 14:10:00','2018-03-01 14:20:00','2018-03-01 14:30:00','2018-03-01 14:40:00','2018-03-01 14:50:00', # 30min, 10min
                #         '2018-03-01 15:10:00','2018-03-01 15:20:00','2018-03-01 18:10:00','2018-03-01 18:20:00','2018-03-01 18:30:00','2018-03-01 18:40:00','2018-03-01 18:50:00',
                #         '2018-03-01 19:10:00','2018-03-01 19:20:00','2018-03-01 19:30:00','2018-03-01 19:40:00','2018-03-01 19:50:00',
                #         #Dia 02
                #         '2018-03-02 04:00:00', # 24H
                #         '2018-03-02 12:00:00','2018-03-02 16:00:00', # 4H
                #         '2018-03-02 14:00:00','2018-03-02 15:00:00','2018-03-02 16:00:00','2018-03-02 17:00:00','2018-03-02 18:00:00','2018-03-02 19:00:00','2018-03-02 20:00:00', # 2H, 1H
                #         '2018-03-02 21:00:00',
                #         '2018-03-02 14:10:00','2018-03-02 14:20:00','2018-03-02 14:30:00','2018-03-02 14:40:00','2018-03-02 14:50:00','2018-03-02 15:10:00','2018-03-02 15:20:00', # 30min, 10min
                #         '2018-03-02 15:30:00','2018-03-02 15:40:00','2018-03-02 15:50:00','2018-03-02 18:10:00','2018-03-02 18:20:00','2018-03-02 18:30:00','2018-03-02 18:40:00',
                #         '2018-03-02 18:50:00','2018-03-02 19:10:00','2018-03-02 19:20:00','2018-03-02 19:30:00','2018-03-02 19:40:00','2018-03-02 19:50:00','2018-03-02 20:10:00'
                #         ]:
                    dataframe = grouped.get_group(i)
                    # remover a coluna do timestamp
                    dataframe = dataframe.drop(columns='Timestamp')
                    # selecionar apenas os flows que tem máquinas internas ou como origem, ou como destino
                    df_internal = dataframe[dataframe[['Src IP','Dst IP']].applymap(lambda x: '172.31.' in str(x))].dropna(how='all')
                    dataframe = dataframe.loc[df_internal.index]
                    day = get_day(file)

                    if (len(dataframe.index) >= 10):
                    # Extrair portos distintos usados para realizar comunicações
                        SrcPortUsed = dataframe[['Src Port','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcPortUsed = SrcPortUsed['Src Port']
                    # Extrair portos distintos contactados
                        SrcPortContacted = dataframe[['Dst Port','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcPortContacted = SrcPortContacted['Dst Port']
                    # Extrair diferentes IPs de destino contactados
                        SrcIPContacted    = dataframe[['Dst IP','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcIPContacted = SrcIPContacted['Dst IP']
                    # Extrair numero total do tamanho de pacotes enviados
                        SrcTotLenSent = dataframe[['TotLen Fwd Pkts','Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                    # Extrair numero total do tamanho de pacotes recebidos
                        SrcTotLenRcv = dataframe[['TotLen Bwd Pkts','Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                    # Extrair numero total de sessões estabelecidas LD
                        SrcTotConn = dataframe[['Dst IP','Src IP']].groupby('Src IP', axis=0, as_index=True).count()

                        print("Src Donne")

                    #  Extrair portos distintos usados para realizar comunicações
                        DstPortUsed = dataframe[['Dst Port','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstPortUsed = DstPortUsed['Dst Port']
                    # Extrair portos distintos contactados
                        DstPortContacted = dataframe[['Src Port','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstPortContacted = DstPortContacted['Src Port'] 
                    #  Extrair diferentes IPs de destino contactados
                        DstIPContacted = dataframe[['Src IP','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstIPContacted = DstIPContacted['Src IP']
                    # Extrair numero total do tamanho de pacotes enviados 
                        DstTotLenSent = dataframe[['TotLen Bwd Pkts','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                    # Extrair numero total do tamanho de pacotes recebidos 
                        DstTotLenRcv = dataframe[['TotLen Fwd Pkts','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                    # Extrair numero total de sessões recebidas LD
                        DstTotConn = dataframe[['Src IP','Dst IP']].groupby('Dst IP', axis=0, as_index=True).count()


                        print("Dst Donne")
                    #print(DstPortUsed.head(5))

                    # df.reset_index(inplace=True)
                    # df.rename({'index':'Dst IP'}, axis='columns', inplace=True)
                    # del df.index.name
                    # decomentar para utilizar a moda do numero de portos contactados/usados
                    # mode_ports = int((SrcPortUsed.mode().max()+SrcPortContacted.mode().max()+DstPortContacted.mode().max()+DstPortUsed.mode().max()))
                    # if mode_ports == 'nan':
                    #     mode_ports =1
                    # print('mean ports - ',mode_ports)

                    # Extrair os portos que cumprem o critério de selecao
                        dataframe.set_index(['Src IP'], inplace=True)
                    # descomentar 'SrcPortContacted, etc..' para usar a moda dos portos contactados
                        port_list_src, port_list_dst = get_ports(dataframe[['Src Port','Dst Port']]) # SrcPortContacted, SrcPortUsed, DstPortContacted, DstPortUsed, mode_ports)
                    #port_list = get_ports(df[['Src Port','Dst Port']])
                    #print('port_list len - ', len(port_list))
                        lenght = len(dataframe) #valente
                        # print(lenght) #valente
                        interval = 0 #valente_2
                        if lenght > 10000:  #valente4 - até linha 504
                            while lenght>=1000:  #valente
                                lenght=int(lenght/2)  #valente
                                interval+=1  #valente
                        # print(interval)  #valente
                            sub_dataframes_index = numpy.linspace(0,len(dataframe),interval, dtype='int64') #valente
                    #print(sub_dataframes_index)
                            low_chunk = 0
                            srcpkt_list, dstpkt_list = [], []
                            for chunk in sub_dataframes_index[1:]:
                                sub_dataframe = dataframe.iloc[low_chunk:chunk]
                                low_chunk = chunk
                        # Extrair os pacotes enviados e recebidos em cada porto do ponto de vista da origem e do destino
                                SrcPkt = get_src_pkts(sub_dataframe, port_list_src)
                                srcpkt_list.append(SrcPkt)
                                sub_dataframe.reset_index(inplace=True)
                                sub_dataframe.set_index(['Dst IP'], inplace=True)
                                DstPkt = get_dst_pkts(sub_dataframe, port_list_dst)
                                dstpkt_list.append(DstPkt)
                        #if len(srcpkt_list)>1:
                            SrcPkt = pd.concat([srcpkt for srcpkt in srcpkt_list], axis=0, sort=False)
                        #else:
                            #SrcPkt = pd.DataFrame(srcpkt_list)
                            SrcPkt = SrcPkt.groupby(SrcPkt.index, axis=0, as_index=True).sum()
                            print("Src pkts extracted")
                        #if len(dstpkt_list)>1:
                            DstPkt = pd.concat([dstpkt for dstpkt in dstpkt_list], axis=0, sort=False)
                        #else:
                        #    DstPkt = dstpkt_list
                        #    print(DstPkt.columns)
                            DstPkt = DstPkt.groupby(DstPkt.index, axis=0, as_index=True).sum()
                            print("Dst pkts extracted")
                        else:
                        	SrcPkt = get_src_pkts(dataframe,port_list_src)
                        	print("Src pkt extracted without chunks")
                        	DstPkt = get_dst_pkts(dataframe, port_list_dst)
                        	print("Dst pkt extracted without chunks") 
                    # # Extrair os pacotes enviados e recebidos em cada porto do ponto de vista da origem e do destino
                    # SrcPkt = get_src_pkts(dataframe, port_list_src)
                    # print ("extracao de src_packets concluida")
                    # dataframe.reset_index(inplace=True)
                    # dataframe.set_index(['Dst IP'], inplace=True)
                    # DstPkt = get_dst_pkts(dataframe, port_list_dst)
                    # print ("extracao de dst_packets concluida")
                    # Concatenacao das features todas
                        if len(SrcPkt)>=1 or len(DstPkt)>=1:
                            Tot = pd.concat([SrcIPContacted, SrcPortUsed, SrcPortContacted, SrcTotLenRcv, SrcTotLenSent, SrcTotConn, SrcPkt, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstTotConn, DstPkt], axis=1,  sort=False) # LD removi  axis=1 , sort=False)
                        # Cria uma lista com os nomes das colunas ordenados de acordo com a concatenação 
                            src_columns = SrcPkt.columns.to_list()
                            dst_columns = DstPkt.columns.to_list()
                            prefix_columns=['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent', 'SrcConnMade']+replace_columns(src_columns) #valente_2
                            prefix_columns+=(['DstIPContacted', 'DstPortUsed', 'DstPortContacted', 'DstTotLenRcv', 'DstTotLenSent', 'DstTotConn']+replace_columns(dst_columns)) #valente_2
                            print (Tot.columns)
                            print ("VE ISTO")
                            print (prefix_columns)
                            Tot.columns = prefix_columns #valente_2
                            del prefix_columns, src_columns, dst_columns
                            gc.collect()
                        # columns = ['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent', 'SrcTotConn'] #LD
                        # columns = columns + src_columns
                        # columns = columns + ['DstIPContacted', 'DstPortUsed', 'DstPortContacted', 'DstTotLenRcv', 'DstTotLenSent', 'DstTotConn'] #LD
                        # columns = columns + dst_columns
                        else:
                            Tot = pd.concat([SrcIPContacted, SrcPortUsed, SrcPortContacted, SrcTotLenRcv, SrcTotLenSent, SrcTotConn, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstTotConn], axis=1, sort=False) # LD removi  axis=1 , sort=False)
                        # Cria uma lista com os nomes das colunas ordenados de acordo com a concatenação 
                            columns = ['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent','SrcTotConn','DstIPContacted', 'DstPortUsed', 'DstPortContacted', 'DstTotLenRcv', 'DstTotLenSent', 'DstTotConn']
                    # Atribui os nomes das colunas da dataframe com base na lista criada anteriormente
                            Tot.columns = columns #valente_2
                            del columns
                        Tot.fillna(value=0, inplace=True)
                        del SrcIPContacted, SrcPortContacted, SrcPortUsed, SrcTotLenRcv, SrcTotLenSent, SrcPkt, SrcTotConn, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstPkt, DstTotConn #LD
                        gc.collect()

                    #print ("shape antes remoçao 0:"+Tot.shape)
                    #apagar colunas a zero LD
                    #Tot = Tot.loc[:, (Tot != 0).any(axis=0)]
                    #print ("shape depois remoçao 0:"+Tot.shape)

                    # Aplicar algoritmos de clustering
                        if len(Tot.index) > 0:
                            i = datetime.strptime(str(i),"%Y-%m-%d %H:%M:%S")
                            i = i.timestamp()-(4*60*60)
                            i = datetime.fromtimestamp(i)
                            print(str(i).split(' ')[-1]) #valente
                        # # Guardar os features extraidas
                            Path(dir_path+'/day'+str(day)+'/'+str(timeWindows)+'min/').mkdir(parents=True, exist_ok=True) #valente2
                            Tot.to_csv('day'+str(day)+'/'+str(timeWindows)+'min/'+str(timeWindows)+'_features_'+str(day)+'_'+str(i).split(' ')[-1]+'.csv') #valente - guardar ficheiros com hora no nome
                        else:
                            print('entities not found')
                        print("Donne")
                        # saved_groups.write(str(i))
                        # saved_groups.write(',')
                        # saved_groups.write(str(k))
                        # saved_groups.write('\n')
                        k+=1
                        del Tot
                        gc.collect()
                    else:
                   	    print('Not enough entities')
            #saved_groups.close()
    del grouped
    print(str(file) + ' extracted')

if __name__ == '__main__' :
    main()
