import React, {useState, useEffect, useCallback} from 'react';
import {
  SafeAreaView, StyleSheet, View, Text, PermissionsAndroid,
  FlatList, ActivityIndicator, TouchableOpacity,
} from 'react-native';
import GetSMS from 'react-native-get-sms-android';

const API_URL = 'https://unpathological-margit-subtransversal.ngrok-free.dev/analyze_url';

const URL_REGEX = /(https?:\/\/[^\s]+)/g;

const MessageItem = ({item}) => {
  const getStatusStyle = status => {
    switch (status) {
      case 'malicious': return styles.malicious;
      case 'suspicious': return styles.suspicious;
      case 'safe': return styles.safe;
      case 'error': return styles.malicious;
      case 'scanning': return styles.scanning;
      default: return styles.pending; // for 'pending'
    }
  };
  return (
    <View style={styles.messageItem}>
      <Text style={styles.sender}>From: {item.sender}</Text>
      <Text style={styles.body}>{item.body}</Text>
      {item.url && (
        <View style={styles.analysisBox}>
          <Text style={styles.urlText}>URL Found: {item.url}</Text>
          {item.status === 'scanning' ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={[styles.statusText, getStatusStyle(item.status)]}>
              {item.status.toUpperCase()}
            </Text>
          )}
          {item.details && <Text style={styles.detailsText}>{item.details}</Text>}
        </View>
      )}
    </View>
  );
};

const App = () => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const analyzeUrl = async (messageId, url) => {
    setMessages(prev => prev.map(m => (m.id === messageId ? {...m, status: 'scanning', details: 'Analyzing...'} : m)));
    try {
      const response = await fetch(API_URL, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}),
      });
      if (!response.ok) throw new Error(`Server responded with status: ${response.status}`);
      const result = await response.json();
      if (result.error) throw new Error(result.error);

      let status = 'safe', details = `0/${result.total || 'N/A'} flagged this.`;
      if (result.positives > 5) status = 'malicious';
      else if (result.positives > 0) status = 'suspicious';
      if (result.positives !== undefined) details = `${result.positives}/${result.total} scanners flagged this.`;

      setMessages(prev => prev.map(msg => (msg.id === messageId ? {...msg, status, details} : msg)));
    } catch (e) {
      console.error('API Error:', e);
      setMessages(prev => prev.map(msg => (msg.id === messageId ? {...msg, status: 'error', details: 'Analysis failed. Check server or rate limit.'} : msg)));
    }
  };

  const getSmsMessages = useCallback(async () => {
    setLoading(true); setError(null); setMessages([]);
    try {
      const hasPermission = await PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.READ_SMS);
      if (hasPermission === PermissionsAndroid.RESULTS.GRANTED) {
        GetSMS.list(
          JSON.stringify({box: 'inbox', maxCount: 250}),
          (fail) => { setError('Failed to get SMS messages.'); setLoading(false); },
          (count, smsList) => {
            let parsedSms = JSON.parse(smsList);
            parsedSms.sort((a, b) => b.date_sent - a.date_sent);

            const messagesWithUrls = parsedSms.map(msg => {
              const urlsFound = msg.body.match(URL_REGEX);
              if (urlsFound && urlsFound.length > 0) {
                return { id: msg._id, sender: msg.address, body: msg.body, url: urlsFound[0], status: 'pending', details: 'In queue for analysis...' };
              }
              return null;
            }).filter(Boolean);

            const messagesToDisplay = messagesWithUrls.slice(0, 50);
            setMessages(messagesToDisplay);
            setLoading(false);

            if (messagesToDisplay.length === 0) return;

            const analyzeAllUrls = async () => {
              for (const msg of messagesToDisplay) {
                if (msg.url) {
                  await analyzeUrl(msg.id, msg.url);
                  await new Promise(resolve => setTimeout(resolve, 16000));
                }
              }
            };
            analyzeAllUrls();
          },
        );
      } else { setError('SMS permission denied.'); setLoading(false); }
    } catch (err) { setError('An error occurred while reading SMS.'); setLoading(false); }
  }, []);

  useEffect(() => { getSmsMessages(); }, [getSmsMessages]);

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerText}>SMS Phishing Detector</Text>
        <TouchableOpacity onPress={getSmsMessages} style={styles.refreshButton}>
          <Text style={styles.refreshButtonText}>Refresh Scan</Text>
        </TouchableOpacity>
        <Text style={styles.infoText}>Showing up to 50 most recent messages with URLs.</Text>
      </View>
      {loading && <ActivityIndicator size="large" style={styles.loader} />}
      {error && <Text style={styles.errorText}>{error}</Text>}
      {!loading && !error && (
        <FlatList
          data={messages} renderItem={({item}) => <MessageItem item={item} />}
          keyExtractor={item => item.id.toString()}
          ListEmptyComponent={<Text style={styles.emptyText}>No messages with URLs found in your recent SMS.</Text>}
        />
      )}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#a9ce5eff'},
  header: {padding: 20, backgroundColor: '#cee7a3ff', alignItems: 'center'},
  headerText: {color: '#fff', fontSize: 24, fontWeight: 'bold'},
  refreshButton: {marginTop: 15, backgroundColor: '#1a8329ff', paddingVertical: 10, paddingHorizontal: 20, borderRadius: 8},
  refreshButtonText: {color: '#fff', fontSize: 16, fontWeight: 'bold'},
  infoText: {color: '#fff', fontSize: 14, textAlign: 'center', marginTop: 10, fontStyle: 'italic', fontWeight: 'bold'} ,
  loader: {marginTop: 50},
  errorText: {color: 'red', textAlign: 'center', marginTop: 20},
  emptyText: {color: '#f1eeeeff', textAlign: 'center', marginTop: 50},
  messageItem: {padding: 15, borderBottomWidth: 1, borderBottomColor: '#42b570ff', backgroundColor: '#0f5b0fff', marginHorizontal: 10, marginVertical: 5, borderRadius: 8},
  sender: {color: '#fff', fontWeight: 'bold', fontSize: 16},
  body: {color: '#ddd', marginTop: 5},
  analysisBox: {backgroundColor: '#739146ff', padding: 10, marginTop: 10, borderRadius: 6},
  urlText: {color: '#fcfbfbff', fontStyle: 'italic', marginBottom: 10},
  statusText: {color: '#fff', fontWeight: 'bold', textAlign: 'center'},
  detailsText: {color: '#e8f0ebff', marginTop: 5, textAlign: 'center', fontSize: 12},
  safe: {backgroundColor: '#28a745', padding: 5, borderRadius: 4},
  suspicious: {backgroundColor: '#ffc107', padding: 5, borderRadius: 4},
  malicious: {backgroundColor: '#dc3545', padding: 5, borderRadius: 4},
  scanning: {backgroundColor: '#17a2b8', padding: 5, borderRadius: 4},
  pending: {backgroundColor: '#3f4d5bff', padding: 5, borderRadius: 4},
});

export default App;