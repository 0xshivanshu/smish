import React, {useState, useEffect, useCallback} from 'react';
import {
  SafeAreaView,
  StyleSheet,
  View,
  Text,
  PermissionsAndroid,
  FlatList,
  ActivityIndicator,
  TouchableOpacity,
  Alert, // Import Alert for the secure scan feedback
} from 'react-native';
import GetSMS from 'react-native-get-sms-android';
import { getOrCreateKeys, createSecurePayload } from './crypto-client';

const API_URL_BASE = 'https://unpathological-margit-subtransversal.ngrok-free.dev';
const URL_REGEX = /(https?:\/\/[^\s]+)/g; // Added 'g' for global search

const ReportSection = ({report}) => {
  if (!report || typeof report.score === 'undefined') {
    return <Text style={{color: 'orange'}}>Invalid Report Data</Text>;
  }
  const getScoreColor = (score) => {
    if (score === -1) return '#6c757d';
    if (score >= 80) return '#dc3545';
    if (score >= 30) return '#ffc107';
    return '#28a745';
  };
  return (
    <View style={styles.reportSection}>
      <View style={styles.reportHeader}>
        <Text style={styles.scannerName}>{report.scanner}</Text>
        {report.score > -1 && <Text style={[styles.scoreText, {color: getScoreColor(report.score)}]}>{report.score}/100</Text>}
      </View>
      <View>
        {report.findings.map((finding, index) => (
          <Text key={index} style={styles.findingText}>• {finding}</Text>
        ))}
      </View>
    </View>
  );
};

const FullAnalysisView = ({analysis}) => {
  if (!analysis || !analysis.reports) return null;
  return (
    <View style={styles.analysisBox}>
      <ReportSection report={analysis.reports.network_analysis} />
      <ReportSection report={analysis.reports.reputation_analysis} />
      <ReportSection report={analysis.reports.behavioral_analysis} />
      <ReportSection report={analysis.reports.application_analysis} />
    </View>
  );
};

// --- Main App Component ---
const App = () => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const analyzeUrl = async (messageId, urlId, url) => {
    const runScanAndUpdate = async (endpoint, reportKey) => {
      updateMessageReport(reportKey, { ...initialAnalysisState.reports[reportKey], findings: ["Scanning..."] });
      try {
        const response = await fetch(`${API_URL_BASE}${endpoint}`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true', 'ngrok-version': '2' },
          body: JSON.stringify({url}),
        });
        if (!response.ok) throw new Error(`API returned an error: ${response.status}`);
        const result = await response.json();
        updateMessageReport(reportKey, result);
      } catch (e) {
        const errorResult = { ...initialAnalysisState.reports[reportKey], score: 100, findings: [`Scan failed. Error: ${e.message}`]};
        updateMessageReport(reportKey, errorResult);
      }
    };
    
    const updateMessageReport = (reportKey, reportData) => {
      setMessages(prev => prev.map(msg => {
        if (msg.id === messageId) {
          const updatedUrls = msg.urls.map(u => {
            if (u.id === urlId) {
              const currentAnalysis = u.analysis || { reports: {} };
              const updatedReports = {...currentAnalysis.reports, [reportKey]: reportData};
              return {...u, analysis: {...currentAnalysis, reports: updatedReports}};
            }
            return u;
          });
          return {...msg, urls: updatedUrls};
        }
        return msg;
      }));
    };

    const initialAnalysisState = {
      reports: {
        network_analysis: { scanner: 'Nmap Scan', findings: ["Queued..."], score: -1 },
        reputation_analysis: { scanner: 'VirusTotal API', findings: ["Pending..."], score: -1 },
        behavioral_analysis: { scanner: 'Sandbox Simulation', findings: ["Pending..."], score: -1 },
        application_analysis: { scanner: 'OWASP ZAP Scan', findings: ["Pending..."], score: -1 },
      }
    };
    
    setMessages(prev => prev.map(msg => {
      if (msg.id === messageId) {
        const updatedUrls = msg.urls.map(u => u.id === urlId ? {...u, isScanning: true, analysis: initialAnalysisState} : u);
        return {...msg, urls: updatedUrls};
      }
      return msg;
    }));

    await new Promise(resolve => setTimeout(resolve, 500));
    
    await runScanAndUpdate('/analyze/network', 'network_analysis');
    await runScanAndUpdate('/analyze/reputation', 'reputation_analysis');
    await runScanAndUpdate('/analyze/behavioral', 'behavioral_analysis');
    await runScanAndUpdate('/analyze/application', 'application_analysis');

    setMessages(prev => prev.map(msg => {
      if (msg.id === messageId) {
        const updatedUrls = msg.urls.map(u => u.id === urlId ? {...u, isScanning: false} : u);
        return {...msg, urls: updatedUrls};
      }
      return msg;
    }));
  };

  const handleScanPress = (messageId, urlId) => {
    const message = messages.find(m => m.id === messageId);
    if (!message) return;
    const urlItem = message.urls.find(u => u.id === urlId);
    if (!urlItem || urlItem.isScanning || urlItem.analysis) return;
    analyzeUrl(messageId, urlId, urlItem.url);
  };
  
  const handleSecureScanPress = async (url) => {
    try {
      console.log("--- Starting Secure Scan Workflow ---");
      Alert.alert("Secure Scan Started", "Check console for progress...");
      const clientKeys = await getOrCreateKeys();
      const clientID = "user123";

      const registerResponse = await fetch(`${API_URL_BASE}/register_client`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
        body: JSON.stringify({ client_id: clientID, public_key: clientKeys.publicKey }),
      });
      if (!registerResponse.ok) throw new Error("Client registration failed.");
      console.log("Client registered.");

      const serverKeyResponse = await fetch(`${API_URL_BASE}/get_server_public_key`);
      const { server_public_key } = await serverKeyResponse.json();
      console.log("Got server public key.");

      const payload = await createSecurePayload(url, clientKeys.privateKey, server_public_key);
      console.log("Secure payload created.");

      const analysisResponse = await fetch(`${API_URL_BASE}/secure_analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
        body: JSON.stringify({ ...payload, client_id: clientID }),
      });
      
      const result = await analysisResponse.json();
      if(analysisResponse.ok) {
        console.log("SECURE ANALYSIS SUCCESS:", result);
        Alert.alert("Secure Analysis Succeeded!", JSON.stringify(result, null, 2));
      } else {
        throw new Error(result.error);
      }
    } catch (e) {
      console.error("SECURE WORKFLOW FAILED:", e);
      Alert.alert(`Secure analysis failed: ${e.message}`);
    }
  };

  const getSmsMessages = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const hasPermission = await PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.READ_SMS);
      if (hasPermission === PermissionsAndroid.RESULTS.GRANTED) {
        GetSMS.list(
          JSON.stringify({maxCount: 200}),
          (fail) => { setError('Failed to read SMS messages.'); setLoading(false); },
          (count, smsList) => {
            const messagesWithUrls = JSON.parse(smsList).map((msg, index) => {
              const urlsFound = msg.body.match(URL_REGEX);
              if (urlsFound && urlsFound.length > 0) {
                return {
                  id: `${msg.date_sent}-${index}`,
                  sender: msg.address,
                  body: msg.body,
                  urls: urlsFound.map((url, urlIndex) => ({
                    id: `${msg.date_sent}-${index}-${urlIndex}`,
                    url: url,
                    isScanning: false, analysis: null, error: null,
                  })),
                };
              }
              return null;
            }).filter(Boolean);
            setMessages(messagesWithUrls);
            setLoading(false);
          },
        );
      } else { setError('SMS permission was denied.'); setLoading(false); }
    } catch (err) { setError('An error occurred.'); setLoading(false); }
  }, []);

  useEffect(() => { getSmsMessages(); }, [getSmsMessages]);
  
  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerText}>Smishing Detector</Text>
        <TouchableOpacity onPress={getSmsMessages} style={styles.refreshButton}>
          <Text style={styles.refreshButtonText}>Refresh</Text>
        </TouchableOpacity>
      </View>
      <FlatList
        data={messages}
        keyExtractor={item => item.id}
        renderItem={({item}) => (
          <View style={styles.messageItem}>
            <Text style={styles.sender}>From: {item.sender}</Text>
            <Text style={styles.body}>{item.body}</Text>
            
            {item.urls.map((urlItem) => (
              <View key={urlItem.id} style={styles.urlContainer}>
                <TouchableOpacity 
                  style={styles.scanButton}
                  onPress={() => handleScanPress(item.id, urlItem.id)} 
                  disabled={!!(urlItem.isScanning || urlItem.analysis)}
                >
                  <Text style={styles.scanButtonText}>
                    {urlItem.analysis ? "Scanning..." : (urlItem.isScanning ? "Scanning..." : `Scan: ${urlItem.url}`)}
                  </Text>
                </TouchableOpacity>
                {urlItem.analysis && <FullAnalysisView analysis={urlItem.analysis} />}
              </View>
            ))}
          </View>
        )}
        ListEmptyComponent={<Text style={styles.emptyText}>No URLs found in recent SMS.</Text>}
      />
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  header: {padding: 15, backgroundColor: '#1c1c1c', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'},
  headerText: {color: '#fff', fontSize: 22, fontWeight: 'bold'},
  refreshButton: {backgroundColor: '#007bff', paddingVertical: 8, paddingHorizontal: 15, borderRadius: 5},
  refreshButtonText: {color: '#fff', fontWeight: 'bold'},
  messageItem: {padding: 15, backgroundColor: '#1c1c1c', marginHorizontal: 10, marginVertical: 6, borderRadius: 8},
  sender: {color: '#fff', fontWeight: 'bold', fontSize: 16},
  body: {color: '#ddd', marginTop: 5, fontSize: 14, lineHeight: 20},
  urlContainer: {borderTopWidth: 1, borderTopColor: '#3a3a3a', marginTop: 15, paddingTop: 15},
  buttonContainer: {flexDirection: 'row', justifyContent: 'space-around', marginBottom: 10},
  scanButton: {backgroundColor: '#007bff', paddingVertical: 10, paddingHorizontal: 15, borderRadius: 5, alignItems: 'center', flex: 1, marginHorizontal: 5},
  secureScanButton: {backgroundColor: '#28a745'},
  scanButtonText: {color: '#fff', fontWeight: 'bold', fontSize: 12, textAlign: 'center'},
  analysisBox: {marginTop: 10, paddingTop: 10},
  reportSection: {backgroundColor: '#2c2c2c', borderRadius: 6, padding: 10, marginBottom: 8},
  reportHeader: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5},
  scannerName: {color: '#eee', fontWeight: 'bold', fontSize: 14},
  scoreText: {fontWeight: 'bold', fontSize: 16},
  findingText: {color: '#ccc', fontStyle: 'italic', marginLeft: 10, marginTop: 3},
  emptyText: {color: '#888', textAlign: 'center', marginTop: 50, fontSize: 16},
});

export default App;