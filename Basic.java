package vmm;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.net.ssl.*;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPFaultException;

import com.vmware.vim25.*;

public class Basic {
	
	private static String url;  
    private static String userName;  
    private static String password;  
    private static String hostname;
  
    private static String[] vmCounterNames = new String[] { "cpu.usagemhz.AVERAGE", "mem.consumed.AVERAGE" };
    private static String[] hostCounterNames = new String[] { "cpu.usagemhz.AVERAGE", "mem.consumed.AVERAGE", "net.usage.AVERAGE" };
    private static HashMap<String, Integer> countersIdMap = new HashMap<String, Integer>();
    private static HashMap<Integer, PerfCounterInfo> countersInfoMap = new HashMap<Integer, PerfCounterInfo>();
    
    private static final ManagedObjectReference SVC_INST_REF = new ManagedObjectReference();  
    private static VimService vimService;  
    private static VimPortType vimPort;  
  
    private static ServiceContent serviceContent;  
    private static final String SVC_INST_NAME = "ServiceInstance";  
    private static Boolean isConnected = false;  
    private static ManagedObjectReference perfManager;  
    private static ManagedObjectReference propCollectorRef;  
    
    private static PerfQuerySpec querySpec;
	private static int threshold = 3000;
  
    // Constructor
    public Basic(String puserName, String ppassWord, String purl, String phostName)  {  
        url = purl;  
        userName = puserName;  
        password = ppassWord;
        hostname = phostName;
    }  
  
    private static class TrustAllTrustManager implements TrustManager, X509TrustManager  {  
        public java.security.cert.X509Certificate[] getAcceptedIssuers()  {  
            return null;  
        }  
  
        public boolean isServerTrusted(java.security.cert.X509Certificate[] certs)  {  
            return true;  
        }  
  
        public boolean isClientTrusted(java.security.cert.X509Certificate[] certs)  {  
            return true;  
        }  
  
        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) throws java.security.cert.CertificateException  {  
            return;  
        }  
  
        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) throws java.security.cert.CertificateException  {  
            return;  
        }  
    }  
  
    private static void trustAllHttpsCertificates() throws Exception  
    {  
        TrustManager[] trustAllCerts = new TrustManager[1];  
        TrustManager tm = new TrustAllTrustManager();  
        trustAllCerts[0] = tm;  
        SSLContext sc = SSLContext.getInstance("SSL");  
        SSLSessionContext sslsc = sc.getServerSessionContext();  
        sslsc.setSessionTimeout(0);  
        sc.init(null, trustAllCerts, null);  
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());  
    }  
  

    public static void connect() throws Exception  
    {  
    	// Declare a host name verifier that will automatically enable
    	// the connection. The host name verifier is invoked during
    	// the SSL handshake.
        HostnameVerifier hv = new HostnameVerifier()  
        {  
            public boolean verify(String urlHostName, SSLSession session)  
            {  
                return true;  
            }
            
        };  
        trustAllHttpsCertificates();  
  
        // Set the default host name verifier to enable the connection.
        HttpsURLConnection.setDefaultHostnameVerifier(hv);  
  
        // Set up the manufactured managed object reference for the ServiceInstance
        SVC_INST_REF.setType(SVC_INST_NAME);  
        SVC_INST_REF.setValue(SVC_INST_NAME);  
  
        // Create a VimService object to obtain a VimPort binding provider.
        // The BindingProvider provides access to the protocol fields
        // in request/response messages. Retrieve the request context
        // which will be used for processing message requests.
        vimService = new VimService();  
        vimPort = vimService.getVimPort();  
        Map<String, Object> ctxt = ((BindingProvider) vimPort).getRequestContext();  
  
        // Store the Server URL in the request context and specify true
        // to maintain the connection between the client and server.
        // The client API will include the Server's HTTP cookie in its
        // requests to maintain the session. If you do not set this to true,
        // the Server will start a new session with each request.
        ctxt.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);  
        ctxt.put(BindingProvider.SESSION_MAINTAIN_PROPERTY, true);  
  
        // Retrieve the ServiceContent object and login
        serviceContent = vimPort.retrieveServiceContent(SVC_INST_REF);  
        vimPort.login(serviceContent.getSessionManager(), userName, password, null);  
        isConnected = true;  
  
        perfManager = serviceContent.getPerfManager();  
        propCollectorRef = serviceContent.getPropertyCollector();  
    }  
  
    public static void disconnect() throws Exception  
    {  
        if (isConnected)  
        {  
            vimPort.logout(serviceContent.getSessionManager());  
        }  
        isConnected = false;  
    }  
  
    private static void printSoapFaultException(SOAPFaultException sfe)  
    {  
        System.out.println("Soap fault: ");  
        if (sfe.getFault().hasDetail())  
        {  
            System.out.println(sfe.getFault().getDetail().getFirstChild().getLocalName());  
        }  
        if (sfe.getFault().getFaultString() != null)  
        {  
            System.out.println("Message: " + sfe.getFault().getFaultString());  
        }  
    }  
	
	
    /**
     * Uses the new RetrievePropertiesEx method to emulate the now deprecated
     * RetrieveProperties method.
     *
     * @param listpfs
     * @return list of object content
     * @throws Exception
     */
    static List<ObjectContent> retrievePropertiesAllObjects(
            List<PropertyFilterSpec> listpfs) {

        RetrieveOptions propObjectRetrieveOpts = new RetrieveOptions();

        List<ObjectContent> listobjcontent = new ArrayList<ObjectContent>();

        try {
            RetrieveResult rslts =
                    vimPort.retrievePropertiesEx(propCollectorRef, listpfs,
                            propObjectRetrieveOpts);
            if (rslts != null && rslts.getObjects() != null
                    && !rslts.getObjects().isEmpty()) {
                listobjcontent.addAll(rslts.getObjects());
            }
            String token = null;
            if (rslts != null && rslts.getToken() != null) {
                token = rslts.getToken();
            }
            while (token != null && !token.isEmpty()) {
                rslts =
                        vimPort.continueRetrievePropertiesEx(propCollectorRef, token);
                token = null;
                if (rslts != null) {
                    token = rslts.getToken();
                    if (rslts.getObjects() != null && !rslts.getObjects().isEmpty()) {
                        listobjcontent.addAll(rslts.getObjects());
                    }
                }
            }
        } catch (SOAPFaultException sfe) {
            printSoapFaultException(sfe);
        } catch (Exception e) {
            System.out.println(" : Failed Getting Contents");
            e.printStackTrace();
        }

        return listobjcontent;
    }
    
	/**
     * @return TraversalSpec specification to get to the VirtualMachine managed
     *         object.
     */
	private static TraversalSpec getVmTraversalSpec()  
	{  
	    TraversalSpec vAppToVM = new TraversalSpec();  
	    vAppToVM.setName("vAppToVM");  
	    vAppToVM.setType("VirtualApp");  
	    vAppToVM.setPath("vm");  
	  
	    TraversalSpec vAppToVApp = new TraversalSpec();  
	    vAppToVApp.setName("vAppToVApp");  
	    vAppToVApp.setType("VirtualApp");  
	    vAppToVApp.setPath("resourcePool");  
	  
	    SelectionSpec vAppRecursion = new SelectionSpec();  
	    vAppRecursion.setName("vAppToVApp");  
	    SelectionSpec vmInVApp = new SelectionSpec();  
	    vmInVApp.setName("vAppToVM");  
	    List<SelectionSpec> vAppToVMSS = new ArrayList<SelectionSpec>();  
	    vAppToVMSS.add(vAppRecursion);  
	    vAppToVMSS.add(vmInVApp);  
	    vAppToVApp.getSelectSet().addAll(vAppToVMSS);  
	  
	    SelectionSpec sSpec = new SelectionSpec();  
	    sSpec.setName("VisitFolders");  
	  
	    TraversalSpec dataCenterToVMFolder = new TraversalSpec();  
	    dataCenterToVMFolder.setName("DataCenterToVMFolder");  
	    dataCenterToVMFolder.setType("Datacenter");  
	    dataCenterToVMFolder.setPath("vmFolder");  
	    dataCenterToVMFolder.setSkip(false);  
	    dataCenterToVMFolder.getSelectSet().add(sSpec);  
	  
	    TraversalSpec traversalSpec = new TraversalSpec();  
	    traversalSpec.setName("VisitFolders");  
	    traversalSpec.setType("Folder");  
	    traversalSpec.setPath("childEntity");  
	    traversalSpec.setSkip(false);  
	    List<SelectionSpec> sSpecArr = new ArrayList<SelectionSpec>();  
	    sSpecArr.add(sSpec);  
	    sSpecArr.add(dataCenterToVMFolder);  
	    sSpecArr.add(vAppToVM);  
	    sSpecArr.add(vAppToVApp);  
	    traversalSpec.getSelectSet().addAll(sSpecArr);  
	    return traversalSpec;  
	}  
	
	
	/**
     * Retrieves the MOREF of the VirtualMachine.
     *
     * @param vmName :
     * @return
	 * @throws InvalidPropertyFaultMsg 
	 * @throws RuntimeFaultFaultMsg 
     */
	private static ManagedObjectReference getVmByVmName(String vmName) throws RuntimeFaultFaultMsg, InvalidPropertyFaultMsg
	{
		ManagedObjectReference retVal = null;
		ManagedObjectReference rootFolder = serviceContent.getRootFolder();
		
		TraversalSpec tSpec = getVmTraversalSpec();
		// Create Property Spec
		PropertySpec propertySpec = new PropertySpec();
		propertySpec.setAll(Boolean.FALSE);
		propertySpec.getPathSet().add("name");
		propertySpec.setType("VirtualMachine");
		
		// Create Object Spec
		ObjectSpec objectSpec = new ObjectSpec();
		objectSpec.setObj(rootFolder);
		objectSpec.setSkip(Boolean.TRUE);
		objectSpec.getSelectSet().add(tSpec);
		
		// Create PropertyFilterSpec using the PropertySpec and ObjectSpec created above.
		PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();
		propertyFilterSpec.getPropSet().add(propertySpec);
		propertyFilterSpec.getObjectSet().add(objectSpec);
		List<PropertyFilterSpec> listpfs = new ArrayList<PropertyFilterSpec>(1);
		listpfs.add(propertyFilterSpec);
		List<ObjectContent> listobjcont = retrievePropertiesAllObjects(listpfs);

		if (listobjcont != null)
		{
			for (ObjectContent oc : listobjcont)
			{
				ManagedObjectReference mr = oc.getObj();
				String vmnm = null;
				List<DynamicProperty> dps = oc.getPropSet();
				if (dps != null)
				{
					for (DynamicProperty dp : dps)
					{
						vmnm = (String) dp.getVal();
					}
				}
				if (vmnm != null && vmnm.equals(vmName))
				{
					retVal = mr;
					break;
				}
			}
		} else {
            System.out.println("The Object Content is Null");
        }
		
		return retVal;
	}
	
//	
//	private static List<List<Long>> getVmData(String vmName, String nameInfo, String groupInfo) throws RuntimeFaultFaultMsg, DatatypeConfigurationException, InvalidPropertyFaultMsg  
//	{  
//	    List<List<Long>> list = new ArrayList<List<Long>>();  
//	    ManagedObjectReference vmmor = getVmByVmName(vmName); 
//
//	    if (vmmor != null)  
//	    { 
//	        List<PerfCounterInfo> cInfo = getPerfCounters();  
//	  
//	        int i = 0;  
//	        Map<Integer, PerfCounterInfo> counters = new HashMap<Integer, PerfCounterInfo>();  
//	        for (Iterator<PerfCounterInfo> it = cInfo.iterator(); it.hasNext();)  
//	        {  
//	            PerfCounterInfo pcInfo = (PerfCounterInfo) it.next();  
//	            counters.put(new Integer(pcInfo.getKey()), pcInfo);  
//	        }  
//	  
//	        List<PerfMetricId> listpermeid = vimPort.queryAvailablePerfMetric(perfManager, vmmor, null, null, new Integer(20));  
//	        ArrayList<PerfMetricId> mMetrics = new ArrayList<PerfMetricId>();  
//	        if (listpermeid != null)  
//	        {  
//	            for (int index = 0; index < listpermeid.size(); ++index)  
//	            {  
//	                if (counters.containsKey(new Integer(listpermeid.get(index).getCounterId())))  
//	                {  
//	                    mMetrics.add(listpermeid.get(index));  
//	                }  
//	            }  
//	        }  
//	        PerfQuerySpec qSpec = new PerfQuerySpec();  
//	        qSpec.setEntity(vmmor);  
//	        qSpec.setMaxSample(new Integer(10));  
//	        qSpec.getMetricId().addAll(mMetrics);  
//	        qSpec.setIntervalId(new Integer(20));  
//	  
//	        List<PerfQuerySpec> qSpecs = new ArrayList<PerfQuerySpec>();  
//	        qSpecs.add(qSpec);  
//	  
//	        List<PerfEntityMetricBase> listpemb = vimPort.queryPerf(perfManager, qSpecs);  
//	        List<PerfEntityMetricBase> pValues = listpemb;  
//	        for (i = 0; i < pValues.size(); i++)  
//	        {  
//	            List<PerfMetricSeries> listpems = ((PerfEntityMetric) pValues.get(i)).getValue();  
////	            List<PerfSampleInfo> listinfo = ((PerfEntityMetric) pValues.get(i)).getSampleInfo();  
//	            for (int vi = 0; vi < listpems.size(); ++vi)  
//	            {  
//	                String printInf = "";  
//	                PerfCounterInfo pci = (PerfCounterInfo) counters.get(new Integer(listpems.get(vi).getId().getCounterId()));  
//	  
//	                if (pci != null)  
//	                {  
//	                    if (pci.getNameInfo().getKey().equalsIgnoreCase(nameInfo) && pci.getGroupInfo().getKey().equalsIgnoreCase(groupInfo))  
//	                    {  
//	                        printInf += vi + ":" + pci.getNameInfo().getSummary() + ":" + pci.getNameInfo().getKey() + ":" + pci.getNameInfo().getLabel() + ":"  
//	                                + pci.getGroupInfo().getKey() + ":" + pci.getGroupInfo().getLabel() + ":" + pci.getGroupInfo().getSummary() + " ";  
//	  
//	                        for (PerfMetricId pmi : mMetrics)  
//	                        {  
//	                            int counterId = pmi.getCounterId();  
//	                            if (counterId == listpems.get(vi).getId().getCounterId())  
//	                            {  
//	                                printInf += "[" + pmi.getCounterId() + ":" + pmi.getInstance() + "]    ";  
//	                            }  
//	                        }  
//	  
//	                        if (listpems.get(vi) instanceof PerfMetricIntSeries)  
//	                        {  
//	                            PerfMetricIntSeries val = (PerfMetricIntSeries) listpems.get(vi);  
//	                            List<Long> lislon = val.getValue();  
//	                            for (Long k : lislon)  
//	                            {  
//	                                printInf += k + " ";  
//	                            }  
//	                            list.add(lislon);  
//	                        }  
//	                        printInf += "   " + pci.getUnitInfo().getKey() + " " + pci.getUnitInfo().getLabel() + " " + pci.getUnitInfo().getSummary();  
//	                        System.out.println(printInf);  
//	                    }  
//	                }  
//	            }  
//	        }  
//	  
//	    }  
//	  
//	    return list;  
//	}  
//	
//	
//	public static double getVmCpuUsageByVmName(String VmName) throws RuntimeFaultFaultMsg, DatatypeConfigurationException, InvalidPropertyFaultMsg  
//	{  
//	    double ans = 0.0;  
//	    List<List<Long>> list = getVmData(VmName, "usagemhz", "cpu");  
//	  
//	    long maxInner = 0;  
//	    int times = 0;  
//	    for (List<Long> listOuter : list)  
//	    {  
//	        long tempInner = 0;  
//	        for (long inner : listOuter)  
//	        {  
//	            tempInner += inner;  
//	        }  
//	        if (tempInner > maxInner)  
//	        {  
//	            maxInner = tempInner;  
//	            times = listOuter.size();  
//	        }  
//	    }  
//	    if (times != 0)  
//	    {  
//	        ans = (double) maxInner / times;  
//	    }  
//	    return ans;  
//	}  
////	
//	
//	private static List<PerfCounterInfo> getPerfCounters()  
//	{  
//	    List<PerfCounterInfo> pciArr = null;  
//	  
//	    try  {  
//	        PropertySpec propertySpec = new PropertySpec();  
//	        propertySpec.setAll(Boolean.FALSE);  
//	        propertySpec.getPathSet().add("perfCounter");  
//	        propertySpec.setType("PerformanceManager");  
//	        List<PropertySpec> propertySpecs = new ArrayList<PropertySpec>();  
//	        propertySpecs.add(propertySpec);  
//	  
//	        ObjectSpec objectSpec = new ObjectSpec();  
//	        objectSpec.setObj(perfManager);  
//	        List<ObjectSpec> objectSpecs = new ArrayList<ObjectSpec>();  
//	        objectSpecs.add(objectSpec);  
//	  
//	        PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();  
//	        propertyFilterSpec.getPropSet().add(propertySpec);  
//	        propertyFilterSpec.getObjectSet().add(objectSpec);  
//	  
//	        List<PropertyFilterSpec> propertyFilterSpecs = new ArrayList<PropertyFilterSpec>();  
//	        propertyFilterSpecs.add(propertyFilterSpec);  
//	  
//	        List<PropertyFilterSpec> listpfs = new ArrayList<PropertyFilterSpec>(10);  
//	        listpfs.add(propertyFilterSpec);  
//	        List<ObjectContent> listobjcont = retrievePropertiesAllObjects(listpfs);  
//	  
//	        if (listobjcont != null)  
//	        {  
//	            for (ObjectContent oc : listobjcont)  
//	            {  
//	                List<DynamicProperty> dps = oc.getPropSet();  
//	                if (dps != null)  
//	                {  
//	                    for (DynamicProperty dp : dps)  
//	                    {  
//	                        List<PerfCounterInfo> pcinfolist = ((ArrayOfPerfCounterInfo) dp.getVal()).getPerfCounterInfo();  
//	                        pciArr = pcinfolist;  
//	                    }  
//	                }  
//	            }  
//	        }  
//	    }  
//	    catch (SOAPFaultException sfe)  
//	    {  
//	        printSoapFaultException(sfe);  
//	    }  
//	    catch (Exception e)  
//	    {  
//	        e.printStackTrace();  
//	    }  
//	    return pciArr;  
//	}  
//
////    static PerfCounterInfo getCounterInfo(
//            List<PerfCounterInfo> counterInfo, String groupName, String counterName) {
//        for (PerfCounterInfo info : counterInfo) {
//            if (info.getGroupInfo().getKey().equals(groupName)
//                    && info.getNameInfo().getKey().equals(counterName)) {
//                return info;
//            }
//        }
//        return null;
//    }

    /**
     * @return TraversalSpec specification to get to the HostSystem managed
     *         object.
     */
    static TraversalSpec getHostSystemTraversalSpec() {
        // Create a traversal spec that starts from the 'root' objects
        // and traverses the inventory tree to get to the Host system.
        // Build the traversal specs bottoms up
        SelectionSpec ss = new SelectionSpec();
        ss.setName("VisitFolders");

        // Traversal to get to the host from ComputeResource
        TraversalSpec computeResourceToHostSystem = new TraversalSpec();
        computeResourceToHostSystem.setName("computeResourceToHostSystem");
        computeResourceToHostSystem.setType("ComputeResource");
        computeResourceToHostSystem.setPath("host");
        computeResourceToHostSystem.setSkip(false);
        computeResourceToHostSystem.getSelectSet().add(ss);

        // Traversal to get to the ComputeResource from hostFolder
        TraversalSpec hostFolderToComputeResource = new TraversalSpec();
        hostFolderToComputeResource.setName("hostFolderToComputeResource");
        hostFolderToComputeResource.setType("Folder");
        hostFolderToComputeResource.setPath("childEntity");
        hostFolderToComputeResource.setSkip(false);
        hostFolderToComputeResource.getSelectSet().add(ss);

        // Traversal to get to the hostFolder from DataCenter
        TraversalSpec dataCenterToHostFolder = new TraversalSpec();
        dataCenterToHostFolder.setName("DataCenterToHostFolder");
        dataCenterToHostFolder.setType("Datacenter");
        dataCenterToHostFolder.setPath("hostFolder");
        dataCenterToHostFolder.setSkip(false);
        dataCenterToHostFolder.getSelectSet().add(ss);

        //TraversalSpec to get to the DataCenter from rootFolder
        TraversalSpec traversalSpec = new TraversalSpec();
        traversalSpec.setName("VisitFolders");
        traversalSpec.setType("Folder");
        traversalSpec.setPath("childEntity");
        traversalSpec.setSkip(false);

        List<SelectionSpec> sSpecArr = new ArrayList<SelectionSpec>();
        sSpecArr.add(ss);
        sSpecArr.add(dataCenterToHostFolder);
        sSpecArr.add(hostFolderToComputeResource);
        sSpecArr.add(computeResourceToHostSystem);
        traversalSpec.getSelectSet().addAll(sSpecArr);
        return traversalSpec;
    }

    
    /**
     * Retrieves the MOREF of the host.
     *
     * @param hostName :
     * @return
     */
    static ManagedObjectReference getHostByHostName(String hostName) {
        ManagedObjectReference retVal = null;
        ManagedObjectReference rootFolder = serviceContent.getRootFolder();
        try {
            TraversalSpec tSpec = getHostSystemTraversalSpec();
            // Create Property Spec
            PropertySpec propertySpec = new PropertySpec();
            propertySpec.setAll(Boolean.FALSE);
            propertySpec.getPathSet().add("name");
            propertySpec.setType("HostSystem");

            // Now create Object Spec
            ObjectSpec objectSpec = new ObjectSpec();
            objectSpec.setObj(rootFolder);
            objectSpec.setSkip(Boolean.TRUE);
            objectSpec.getSelectSet().add(tSpec);

            // Create PropertyFilterSpec using the PropertySpec and ObjectPec
            // created above.
            PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();
            propertyFilterSpec.getPropSet().add(propertySpec);
            propertyFilterSpec.getObjectSet().add(objectSpec);
            List<PropertyFilterSpec> listpfs =
                    new ArrayList<PropertyFilterSpec>(1);
            listpfs.add(propertyFilterSpec);
            List<ObjectContent> listobjcont =
                    retrievePropertiesAllObjects(listpfs);

            if (listobjcont != null) {
                for (ObjectContent oc : listobjcont) {
                    ManagedObjectReference mr = oc.getObj();
                    String hostnm = null;
                    List<DynamicProperty> listDynamicProps = oc.getPropSet();
                    DynamicProperty[] dps =
                            listDynamicProps
                                    .toArray(new DynamicProperty[listDynamicProps.size()]);
                    if (dps != null) {
                        for (DynamicProperty dp : dps) {
                            hostnm = (String) dp.getVal();
                        }
                    }
                    if (hostnm != null && hostnm.equals(hostName)) {
                        retVal = mr;
                        break;
                    }
                }
            } else {
                System.out.println("The Object Content is Null");
            }
        } catch (SOAPFaultException sfe) {
            printSoapFaultException(sfe);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return retVal;
    }
//
//    static Object getDynamicProperty(ManagedObjectReference mor,
//                              String propertyName) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
//        ObjectContent[] objContent =
//                getObjectProperties(mor, new String[]{propertyName});
//
//        Object propertyValue = null;
//        if (objContent != null) {
//            List<DynamicProperty> listdp = objContent[0].getPropSet();
//            if (listdp != null) {
//                /*
//                * Check the dynamic property for ArrayOfXXX object
//                */
//                Object dynamicPropertyVal = listdp.get(0).getVal();
//                String dynamicPropertyName =
//                        dynamicPropertyVal.getClass().getName();
//                if (dynamicPropertyName.indexOf("ArrayOf") != -1) {
//                    String methodName =
//                            dynamicPropertyName.substring(
//                                    dynamicPropertyName.indexOf("ArrayOf")
//                                            + "ArrayOf".length(),
//                                    dynamicPropertyName.length());
//                    /*
//                    * If object is ArrayOfXXX object, then get the XXX[] by
//                    * invoking getXXX() on the object.
//                    * For Ex:
//                    * ArrayOfManagedObjectReference.getManagedObjectReference()
//                    * returns ManagedObjectReference[] array.
//                    */
//                    if (methodExists(dynamicPropertyVal, "get" + methodName, null)) {
//                        methodName = "get" + methodName;
//                    } else {
//                        /*
//                        * Construct methodName for ArrayOf primitive types
//                        * Ex: For ArrayOfInt, methodName is get_int
//                        */
//                        methodName = "get_" + methodName.toLowerCase();
//                    }
//                    Method getMorMethod =
//                            dynamicPropertyVal.getClass().getDeclaredMethod(
//                                    methodName, (Class[]) null);
//                    propertyValue =
//                            getMorMethod.invoke(dynamicPropertyVal, (Object[]) null);
//                } else if (dynamicPropertyVal.getClass().isArray()) {
//                    /*
//                    * Handle the case of an unwrapped array being deserialized.
//                    */
//                    propertyValue = dynamicPropertyVal;
//                } else {
//                    propertyValue = dynamicPropertyVal;
//                }
//            }
//        }
//        return propertyValue;
//    }
//
//    
//    /**
//     * Retrieve contents for a single object based on the property collector
//     * registered with the service.
//     *
//     * @param mobj       Managed Object Reference to get contents for
//     * @param properties names of properties of object to retrieve
//     * @return retrieved object contents
//     */
//    static ObjectContent[] getObjectProperties(
//            ManagedObjectReference mobj, String[] properties) {
//        if (mobj == null) {
//            return null;
//        }
//        PropertyFilterSpec spec = new PropertyFilterSpec();
//        spec.getPropSet().add(new PropertySpec());
//        if ((properties == null || properties.length == 0)) {
//            spec.getPropSet().get(0).setAll(Boolean.TRUE);
//        } else {
//            spec.getPropSet().get(0).setAll(Boolean.FALSE);
//        }
//        spec.getPropSet().get(0).setType(mobj.getType());
//        spec.getPropSet().get(0).getPathSet().addAll(Arrays.asList(properties));
//        spec.getObjectSet().add(new ObjectSpec());
//        spec.getObjectSet().get(0).setObj(mobj);
//        spec.getObjectSet().get(0).setSkip(Boolean.FALSE);
//        List<PropertyFilterSpec> listpfs = new ArrayList<PropertyFilterSpec>(1);
//        listpfs.add(spec);
//        List<ObjectContent> listobjcont = retrievePropertiesAllObjects(listpfs);
//        return listobjcont.toArray(new ObjectContent[listobjcont.size()]);
//    }

    /**
     * Determines of a method 'methodName' exists for the Object 'obj'.
     *
     * @param obj            The Object to check
     * @param methodName     The method name
     * @param parameterTypes Array of Class objects for the parameter types
     * @return true if the method exists, false otherwise
     */
    @SuppressWarnings("rawtypes")
	static boolean methodExists(Object obj, String methodName,
                         Class[] parameterTypes) {
        boolean exists = false;
        try {
            Method method = obj.getClass().getMethod(methodName, parameterTypes);
            if (method != null) {
                exists = true;
            }
        } catch (SOAPFaultException sfe) {
            printSoapFaultException(sfe);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return exists;
    }
	/**
	 * 
	 * @param vimPort
	 * @param serviceContent
	 * @param obj
	 * @param logger
	 * @param vmORhost (0 for vm, 1 for host)
	 * @return
	 * @throws Exception
	 */
    static boolean monitorPerformance(VimPortType vimPort, ServiceContent serviceContent, ManagedObjectReference obj,
			Logger logger, int vmORhost) throws Exception {
    	boolean res = false;
    	ManagedObjectReference perfManager = serviceContent.getPerfManager();
		ManagedObjectReference propCollector = serviceContent.getPropertyCollector();
		
		if (countersIdMap.size() == 0) {
			ObjectSpec oSpec = new ObjectSpec();
			oSpec.setObj(perfManager);

			PropertySpec pSpec = new PropertySpec();
			pSpec.setType("PerformanceManager");
			pSpec.getPathSet().add("perfCounter");

			PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();
			propertyFilterSpec.getObjectSet().add(oSpec);
			propertyFilterSpec.getPropSet().add(pSpec);

			
			List<PropertyFilterSpec> listpfs = new ArrayList<PropertyFilterSpec>(1);
			listpfs.add(propertyFilterSpec);
			
			List<ObjectContent> props = retrievePropertiesAllObjects(listpfs);
			
			List<PerfCounterInfo> perfCounters = new ArrayList<PerfCounterInfo>();
			if (props != null) {
				for (ObjectContent oc : props) {
					ManagedObjectReference mr = oc.getObj();
					List<DynamicProperty> dps = oc.getPropSet();
					if (dps != null) {
						for (DynamicProperty dp : dps) {
							perfCounters = ((ArrayOfPerfCounterInfo) dp.getVal()).getPerfCounterInfo();
						}
					}
				}
			}
			
			for (PerfCounterInfo perfCounter : perfCounters) {
				Integer counterId = new Integer(perfCounter.getKey());
				countersInfoMap.put(counterId, perfCounter);
				String counterGroup = perfCounter.getGroupInfo().getKey();
				String counterName = perfCounter.getNameInfo().getKey();
				String counterRollupType = perfCounter.getRollupType().toString();
				String fullCounterName = counterGroup + "." + counterName + "." + counterRollupType;
				// System.out.println(fullCounterName + " : " + counterId);
				countersIdMap.put(fullCounterName, counterId);
			}
		}
		
		List<PerfMetricId> perfMetricIds = new ArrayList<PerfMetricId>();
		if(vmORhost == 0) {
			// vm
			for (int i = 0; i < vmCounterNames.length; i++) {
				PerfMetricId metricId = new PerfMetricId();
				metricId.setCounterId(countersIdMap.get(vmCounterNames[i]));
				metricId.setInstance("");
				perfMetricIds.add(metricId);
			}
		} else {
			// host
			for (int i = 0; i < hostCounterNames.length; i++) {
				PerfMetricId metricId = new PerfMetricId();
				metricId.setCounterId(countersIdMap.get(hostCounterNames[i]));
				metricId.setInstance("");
				perfMetricIds.add(metricId);
			}
		}

		int intervalId = 20;
		PerfQuerySpec querySpecification = new PerfQuerySpec();
		querySpecification.setEntity(obj);
		querySpecification.setIntervalId(intervalId);
		querySpecification.setFormat("csv");
		querySpecification.getMetricId().addAll(perfMetricIds);
		querySpecification.setMaxSample(new Integer(1));

		List<PerfQuerySpec> pqsList = new ArrayList<PerfQuerySpec>();
		pqsList.add(querySpecification);

		List<PerfEntityMetricBase> retrievedStats = vimPort.queryPerf(perfManager, pqsList);

		for (PerfEntityMetricBase singleEntityPerfStats : retrievedStats) {

			PerfEntityMetricCSV entityStatsCsv = (PerfEntityMetricCSV) singleEntityPerfStats;
			List<PerfMetricSeriesCSV> metricsValues = entityStatsCsv.getValue();

			if (metricsValues.isEmpty()) {
				System.out.println("No stats retrieved.");
				throw new Exception();
			}

			//String csvTimeInfoAboutStats = entityStatsCsv.getSampleInfoCSV();

			for (PerfMetricSeriesCSV csv : metricsValues) {

				PerfCounterInfo pci = countersInfoMap.get(csv.getId().getCounterId());

				String key = pci.getGroupInfo().getKey() + "." + pci.getNameInfo().getKey() + "." + pci.getRollupType();
				if (pci.getGroupInfo().getKey().equals("mem")) {
					logger.info(key + " : " + (Integer.parseInt(csv.getValue()) / 1024) + " MB");
				} else {
					logger.info(key + " : " + csv.getValue() + " " + pci.getUnitInfo().getKey());
					if (Integer.parseInt(csv.getValue()) >= threshold) {
						res = true;
					}
				}
			}
		}
		System.out.println("----------------------------------------");
		return res;
		
    }
    
    
    
	public static void main(String[] args) throws Exception  
    {  
        new Basic("vsphere.local\\CloudComputing", "CSE612@2017", "https://128.230.247.56/sdk","128.230.208.175");  

        connect();
        
        String vmname = "CloudComputing04";
        //double CPUUsage = getVmCpuUsageByVmName(vmname);
        //System.out.printf(vmname + " CPU Usage: " + CPUUsage + " megaHertz" +"\n" );
     
        
		// Get virtual machine
		ManagedObjectReference vmMOR = getVmByVmName(vmname);
		if (vmMOR == null) {
			System.out.println("VM not found.");
			return;
		}
		
		// Get host
		ManagedObjectReference hostMOR = getHostByHostName(hostname);
		if (hostMOR == null) {
			System.out.println("Host not found.");
			return;
		}
		
		// create log object for host and vm
		Logger hostLog = Logger.getLogger("loggerHost");
		Logger vmLog = Logger.getLogger("loggerVm");
		FileHandler hostFH;
		FileHandler vmFH;
		
		try {
			hostFH = new FileHandler("log/hostLog.txt");
			vmFH = new FileHandler("log/vmLog.txt");
			hostLog.addHandler(hostFH);
			vmLog.addHandler(vmFH);
			SimpleFormatter formatter = new SimpleFormatter();
			hostFH.setFormatter(formatter);
			vmFH.setFormatter(formatter);

		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// Retrieve Performance Stats
		try {
			while (true) {
				Monitor m = new Monitor(vimPort, serviceContent, hostMOR, vmMOR, hostLog, vmLog);
				m.run();
				Thread.sleep(10 * 1000);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return;
		} finally {
			disconnect();
			vimPort.logout(serviceContent.getSessionManager());
		}
	}	
}

class Monitor implements Runnable {
	VimPortType vimPort;
	ServiceContent serviceContent;
	ManagedObjectReference hostMOR;
	ManagedObjectReference vmMOR;
	Logger hostLog;
	Logger vmLog;

	Monitor(VimPortType vimPort, ServiceContent serviceContent, ManagedObjectReference hostMOR, ManagedObjectReference vmMOR,
			Logger hostLog, Logger vmLog) {
		this.vimPort = vimPort;
		this.serviceContent = serviceContent;
		this.hostMOR = hostMOR;
		this.vmMOR = vmMOR;
		this.hostLog = hostLog;
		this.vmLog = vmLog;
	}

	public void run() {
		try {
			Basic.monitorPerformance(vimPort, serviceContent, vmMOR, vmLog, 0);
			Basic.monitorPerformance(vimPort, serviceContent, hostMOR, hostLog, 1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}



