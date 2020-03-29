'''
    Script to apply feature extraction;
    How to use:  pyhton3 feature_extractor.py <path to flow files>
    Example: time python3 feature_extractor.py old_wednesday_16_02_18.csv
'''
import sys
import time
import pandas as pd
import numpy
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering, ward_tree
from sklearn.preprocessing import MinMaxScaler
from pathlib import Path 
import os 
import gc
import joblib
from datetime import datetime
columns_com_prefixo = []

'''
    Function to extract the day from file name 
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
    Function to restrict the timewindows to each day,
    because there are flows with later dates than the day in analysis
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

# Function to port extraction to be consider features
def get_ports(df): 
    #list_ports = [21,22,23,25,53,67,68,80,123,135,137,138,139,194,443,445,500,1900,1920,2181,2816,3128,3389,5355,6188,6667,7112,8080,8443,10397,27017,30303,50010]
    #list_ports_reia = [80, 194, 25, 22]  
    #portos_ataques_especificos = [21]   
    most_used_ports_dst = df['Dst Port'].value_counts()
    most_used_ports = most_used_ports_dst
    most_used_ports_src = df['Src Port'].value_counts()
    most_used_ports = most_used_ports_dst.append(most_used_ports_src) #
    portosSrc_pref = [] 
    portosDst_pref = []
    list_ports = []
    portosSrc = []
    portosDst = []       
    method = 3  # mothod == 1 Outgene;  method == 2 5050; method == 3  top,uncommon,min  ; method == 4 test
    num_portos = 100
    global columns_com_prefixo
    columns_com_prefixo = []
    if method == 1:
    	list_ports = [80, 194, 25, 22]
    	print ("Outgene ports selected ______________________________")
    
    if method == 2:
    	for i in most_used_ports.sort_values(ascending=False).keys():   
    		if len(list_ports)<=num_portos/2:  #LD  num_portos 							#detects top talkers
    			if i not in list_ports:
    				if i < 49151:      #  < 49151  65535    and i!=8080 and i!=53 
    					list_ports.append(i) 
    					print (i)
    	print ("Above is TOP Count ports selected ______________________________")
    	for i in most_used_ports.sort_values(ascending=True).keys():      
    		if len(list_ports)<=num_portos: # *2 num_portos*2
    			if i not in list_ports:
    				if i < 49151: #    1024 or i==3389		# detects port-scans   - find unique ports, only used once, in well known ports range.
    					list_ports.append(i)
    					print (i)
    	print ("Above is MIN count ports selected ______________________________")
   
    if method == 3:
        df.reset_index(inplace=True)
        aux = df.groupby(['Dst Port']).nunique()
        aux.index.name = None
        uniqueport = aux.sort_values(by=['Src IP'],ascending=False)
        uniqueports= uniqueport[uniqueport['Src IP']<10].index.tolist() #uniqueports is a list of ports contacted by less the 10 IPs 

        for i in most_used_ports.sort_values(ascending=False).keys():   
            if len(list_ports) <= num_portos/3:  
                if i not in list_ports:
                    if i < 49151:
                        list_ports.append(i) 
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('T'+j+'SrcTo') 
                        portosSrc_pref.append('T'+j+'SrcFrom') 
                        portosDst_pref.append('T'+j+'DstTo')
                        portosDst_pref.append('T'+j+'DstFrom') 
                        # Ports without prefix
                        portosSrc.append(j+'SrcTo') 
                        portosSrc.append(j+'SrcFrom') 
                        portosDst.append(j+'DstTo')
                        portosDst.append(j+'DstFrom')
            if len(list_ports) <=  2*num_portos/3: 
                if i not in list_ports and i in uniqueports:
                    if i < 49151:
                        list_ports.append(i)
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('U'+j+'SrcTo') 
                        portosSrc_pref.append('U'+j+'SrcFrom') 
                        portosDst_pref.append('U'+j+'DstTo') 
                        portosDst_pref.append('U'+j+'DstFrom') 
                        #Ports without prefix
                        portosSrc.append(j+'SrcTo') 
                        portosSrc.append(j+'SrcFrom') 
                        portosDst.append(j+'DstTo') 
                        portosDst.append(j+'DstFrom') 
        print ("Above is TOP Count ports selected ______________________________")
        print ("Above is unique contacted port selected ______________________________")

        for i in most_used_ports.sort_values(ascending=True).keys():      
            if len(list_ports) <= num_portos:
                if i not in list_ports:
                    if i <  1024 or i==3389:
                        list_ports.append(i)
                        print (i)
                        j = str(i)
                        portosSrc_pref.append('M'+j+'SrcTo') 
                        portosSrc_pref.append('M'+j+'SrcFrom') 
                        portosDst_pref.append('M'+j+'DstTo') 
                        portosDst_pref.append('M'+j+'DstFrom')
                        # Ports without prefix
                        portosSrc.append(j+'SrcTo') 
                        portosSrc.append(j+'SrcFrom') 
                        portosDst.append(j+'DstTo') 
                        portosDst.append(j+'DstFrom')
        print ("Above is MIN count ports selected ______________________________")
        columns_com_prefixo+=(portosSrc_pref+portosDst_pref)
   
    if method == 4:
        for i in most_used_ports.sort_values(ascending=False).keys():
            if len(list_ports)<=num_portos:  
                if i not in list_ports:
                    if i < 49151:
                        list_ports.append(i)
                        print (i)
        print ("Above is TOP Count ports selected ______________________________")
    
    if method != 3:
        for j in list_ports:
            j = str(j)
            portosSrc.append(j+'SrcTo') 
            portosSrc.append(j+'SrcFrom') 
            portosDst.append(j+'DstTo') 
            portosDst.append(j+'DstFrom')
    return portosSrc, portosDst

# function to extract values of each feature related with ports from source point of view
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

# function to extract values of each feature related with ports from destination point of view
def get_dst_pkts(df, list_ports):
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
        if isinstance(df.get_group(i)['Src Port'].values, numpy.ndarray):
            k=0
            for port in df.get_group(i)['Src Port'].values:
                if (str(port)+'DstFrom') in new_df.columns:
                    new_df.at[i, str(port)+'DstFrom'] += df.get_group(i)['Tot Fwd Pkts'].values[k]+1
                k+=1
        elif(str(df.get_group(i)['Src Port'].values)+'DstFrom') not in new_df.columns:
            new_df.at[i, str(port)+'DstFrom'] += df.get_group(i)['Tot Fwd Pkts'].values+1
    new_df = new_df.loc[:, (new_df != 0).any(axis=0)]
    return new_df

# Function to replace columns name 
def replace_columns(old_columns):
    global columns_com_prefixo
    if len(columns_com_prefixo) == 0:
        return old_columns
    prefix_columns_partial = []
    for col_simple in old_columns:
        for col_prefix in columns_com_prefixo:
            if (str(col_prefix).find(col_simple) != -1) and len(col_prefix)==(len(col_simple)+1):
                prefix_columns_partial.append(col_prefix)
    return prefix_columns_partial

def main():
    files = sys.argv[1:]
    dir_path = os.path.dirname(os.path.realpath(__file__))
    for file in files:
        tempo =time.time()
        df_timestamp = []
        for chunk in pd.read_csv(file, sep=',', dtype='object', chunksize=100000):
            df_timestamp.append(chunk)
        df_timestamp = pd.concat(df_timestamp)
        print("Donne reading csv")
        print(time.time()-tempo)
        # fill NaN fields
        df_timestamp = df_timestamp.fillna(0)
        # remove lines from duplicate header
        df_timestamp = df_timestamp[df_timestamp['Src Port'].map(lambda x: str(x)!="Src Port")]
        # remove lines without timestamp
        df_timestamp = df_timestamp[df_timestamp['Timestamp'].map(lambda x: str(x)!='0')]
        # convert all types of data
        df_timestamp['Src Port'] = df_timestamp['Src Port'].astype('int64')
        df_timestamp['Dst Port'] = df_timestamp['Dst Port'].astype('int64')
        df_timestamp['Tot Fwd Pkts'] = df_timestamp['Tot Fwd Pkts'].astype('int64')
        df_timestamp['Tot Bwd Pkts'] = df_timestamp['Tot Bwd Pkts'].astype('int64')
        df_timestamp['TotLen Fwd Pkts'] = df_timestamp['TotLen Fwd Pkts'].astype('float64')
        df_timestamp['TotLen Bwd Pkts'] = df_timestamp['TotLen Bwd Pkts'].astype('float64')

        timestamp = df_timestamp['Timestamp'].tolist()
        timestamp = pd.to_datetime(timestamp, format="%d/%m/%Y %I:%M:%S %p")
        df_timestamp['Timestamp'] = timestamp

        print("time converted")
        k,m=0,0
        day = get_day(file)
        start_date, end_date = date(day)
        for timeWindows in [10,60,240,480,1440]: 
            grouped = df_timestamp.groupby(by=pd.Grouper(key='Timestamp', freq=str(timeWindows*60)+'s'))
            for i in grouped.indices.keys(): 
                if (i-start_date).total_seconds()>=0 and (i-end_date).total_seconds()<=86400:
                    print(str(i))
                    dataframe = grouped.get_group(i)
                    # remove timestamp column
                    dataframe = dataframe.drop(columns='Timestamp')
                    # select onlyy the flows with internal machines as source or destination 
                    df_internal = dataframe[dataframe[['Src IP','Dst IP']].applymap(lambda x: '172.31.' in str(x))].dropna(how='all')
                    dataframe = dataframe.loc[df_internal.index]
                    day = get_day(file)

                    if (len(dataframe.index) >= 10):
                    # FROM SOURCE POINT OF VIEW 
                    # Extract distinct ports used for communications
                        SrcPortUsed = dataframe[['Src Port','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcPortUsed = SrcPortUsed['Src Port']
                    # Extract distinct ports contacted 
                        SrcPortContacted = dataframe[['Dst Port','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcPortContacted = SrcPortContacted['Dst Port']
                    # Extract diferent detination IPs contacted 
                        SrcIPContacted    = dataframe[['Dst IP','Src IP']].groupby('Src IP', axis=0, as_index=True).nunique()
                        SrcIPContacted = SrcIPContacted['Dst IP']
                    # Extract total # of sent packets size 
                        SrcTotLenSent = dataframe[['TotLen Fwd Pkts','Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                    # Extract total # of received packets size 
                        SrcTotLenRcv = dataframe[['TotLen Bwd Pkts','Src IP']].groupby('Src IP', axis=0, as_index=True).sum()
                    # Extract # of total sessions established LD
                        SrcTotConn = dataframe[['Dst IP','Src IP']].groupby('Src IP', axis=0, as_index=True).count()
                        print("Src Donne")
                        
                    # FROM DESTINADION POINT OF VIEW
                    #  Extract distinct ports used to perform communications
                        DstPortUsed = dataframe[['Dst Port','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstPortUsed = DstPortUsed['Dst Port']
                    # Extract distinct ports contacted 
                        DstPortContacted = dataframe[['Src Port','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstPortContacted = DstPortContacted['Src Port'] 
                    # Extract diferent detination IPs contacted
                        DstIPContacted = dataframe[['Src IP','Dst IP']].groupby('Dst IP', axis=0, as_index=True).nunique()
                        DstIPContacted = DstIPContacted['Src IP']
                    # Extract total # of sent packets size 
                        DstTotLenSent = dataframe[['TotLen Bwd Pkts','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                    # Extract total # of received packets size 
                        DstTotLenRcv = dataframe[['TotLen Fwd Pkts','Dst IP']].groupby('Dst IP', axis=0, as_index=True).sum()
                    # Extract # of total sessions established  LD
                        DstTotConn = dataframe[['Src IP','Dst IP']].groupby('Dst IP', axis=0, as_index=True).count()

                        print("Dst Donne")
                        
                        dataframe.set_index(['Src IP'], inplace=True)
                        port_list_src, port_list_dst = get_ports(dataframe[['Src Port','Dst Port']]) 
                     # Setting conditions to perform port extraction by chunks
                        lenght = len(dataframe) 
                        interval = 0 
                        if lenght > 10000:  
                            while lenght>=1000:  
                                lenght=int(lenght/2)  
                                interval+=1  
                            sub_dataframes_index = numpy.linspace(0,len(dataframe),interval, dtype='int64')
                            low_chunk = 0
                            srcpkt_list, dstpkt_list = [], []
                            for chunk in sub_dataframes_index[1:]:
                                sub_dataframe = dataframe.iloc[low_chunk:chunk]
                                low_chunk = chunk
                        # Extract packets sent and received in each port from source and destination point of view
                                SrcPkt = get_src_pkts(sub_dataframe, port_list_src)
                                srcpkt_list.append(SrcPkt)
                                sub_dataframe.reset_index(inplace=True)
                                sub_dataframe.set_index(['Dst IP'], inplace=True)
                                DstPkt = get_dst_pkts(sub_dataframe, port_list_dst)
                                dstpkt_list.append(DstPkt)
                            SrcPkt = pd.concat([srcpkt for srcpkt in srcpkt_list], axis=0, sort=False)
                            SrcPkt = SrcPkt.groupby(SrcPkt.index, axis=0, as_index=True).sum()
                            print("Src pkts extracted")
                            DstPkt = pd.concat([dstpkt for dstpkt in dstpkt_list], axis=0, sort=False)
                            DstPkt = DstPkt.groupby(DstPkt.index, axis=0, as_index=True).sum()
                            print("Dst pkts extracted")
                        else:
                        	SrcPkt = get_src_pkts(dataframe,port_list_src)
                        	print("Src pkt extracted without chunks")
                        	DstPkt = get_dst_pkts(dataframe, port_list_dst)
                        	print("Dst pkt extracted without chunks") 
                        # Concatenation of all features 
                        if len(SrcPkt)>=1 or len(DstPkt)>=1:
                            Tot = pd.concat([SrcIPContacted, SrcPortUsed, SrcPortContacted, SrcTotLenRcv, SrcTotLenSent, SrcTotConn, SrcPkt, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstTotConn, DstPkt], axis=1,  sort=False) 
                        # Creates a list with column names sorted by concatenation order
                            src_columns = SrcPkt.columns.to_list()
                            dst_columns = DstPkt.columns.to_list()
                            prefix_columns=['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent', 'SrcConnMade']+replace_columns(src_columns)
                            prefix_columns+=(['DstIPContacted', 'DstPortUsed', 'DstPortContacted', 'DstTotLenRcv', 'DstTotLenSent', 'DstTotConn']+replace_columns(dst_columns)) 
                            Tot.columns = prefix_columns 
                            del prefix_columns, src_columns, dst_columns
                            gc.collect()
                        else:
                            Tot = pd.concat([SrcIPContacted, SrcPortUsed, SrcPortContacted, SrcTotLenRcv, SrcTotLenSent, SrcTotConn, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstTotConn], axis=1, sort=False)
                            columns = ['SrcIPContacted', 'SrcPortUsed', 'SrcPortContacted', 'SrcTotLenRcv', 'SrcTotLenSent','SrcTotConn','DstIPContacted', 'DstPortUsed', 'DstPortContacted', 'DstTotLenRcv', 'DstTotLenSent', 'DstTotConn']
                    # Replace dataframe column names by the names stores previosly in a list
                            Tot.columns = columns 
                            del columns
                        Tot.fillna(value=0, inplace=True)
                        del SrcIPContacted, SrcPortContacted, SrcPortUsed, SrcTotLenRcv, SrcTotLenSent, SrcPkt, SrcTotConn, DstIPContacted, DstPortUsed, DstPortContacted, DstTotLenRcv, DstTotLenSent, DstPkt, DstTotConn 
                        gc.collect()

                    # Save features file
                        if len(Tot.index) > 0:
                            i = datetime.strptime(str(i),"%Y-%m-%d %H:%M:%S")
                            i = i.timestamp()-(4*60*60)
                            i = datetime.fromtimestamp(i)
                            print(str(i).split(' ')[-1]) 
                            Path(dir_path+'/day'+str(day)+'/'+str(timeWindows)+'min/').mkdir(parents=True, exist_ok=True) 
                            Tot.to_csv('day'+str(day)+'/'+str(timeWindows)+'min/'+str(timeWindows)+'_features_'+str(day)+'_'+str(i).split(' ')[-1]+'.csv')
                        else:
                            print('entities not found')
                        print("Donne")
                        k+=1
                        del Tot
                        gc.collect()
                    else:
                   	    print('Not enough entities')
    del grouped
    print(str(file) + ' extracted')

if __name__ == '__main__' :
    main()
