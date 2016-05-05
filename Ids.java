// Philip Wipf
// Evgenia Kolotiouk
// CSCI 476 Security Lab 5
// 19 April 2016

// This program accepts a policy file and a .pcap trace file as arguments and attempts to
// match the policy, printing out an alert if the policy matches.

// If no arguments are supplied, goes through all the tests for the lab 5

/*
 * Note: some pcap code taken directly from jnetpcap example 2 at
 * http://jnetpcap.com/?q=tutorial/usage
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

public class Ids {

    // set to automatically run all tests for lab 5 instead of using command line args
    final static String baseDir="";

    static PolicyFile mPolicyFile;
    static Pcap pcap;


    public static void main(String[] args){
        // check for filename argument
        if(args.length<2){
            //System.out.println("Please put proper files on command line");
            //return;

            //instead of exiting with no arguments, run default traces and policies for the lab
            for(int pol=1; pol<=5; pol++){
                for(int trace=1; trace<=5; trace++){
                    boolean runTest=false;
                    switch(pol){
                        case 1:
                            if(trace==1||trace==2||trace==3){
                                runTest=true;
                            }
                            break;
                        case 2:
                            if(trace==1||trace==2||trace==3){
                                runTest=true;
                            }
                            break;
                        case 3:
                            if(trace==1||trace==2||trace==3){
                                runTest=true;
                            }
                            break;
                        case 4:
                            if(trace==4){
                                runTest=true;
                            }
                            break;
                        case 5:
                            if(trace==5){
                                runTest=true;
                            }
                            break;
                    }
                    if(runTest){
                        System.out.println(String.format("policy%d.txt", pol));
                        System.out.println(String.format("trace%d.pcap", trace));
                        runIDS(String.format("%spolicy%d.txt", baseDir, pol)
                                ,String.format("%strace%d.pcap", baseDir, trace));
                    System.out.println();
                    }
                }
                System.out.println();
            }
        }else{

            runIDS(args[0], args[1]);

        }
    }


    public static void runIDS(String policyPath, String tracePath){

       // make a new Policy object from the policy file
       mPolicyFile=new PolicyFile();
       if(!mPolicyFile.readIn(policyPath)){
          System.err.println("Error parsing "+policyPath);
          return;
       }
       mPolicyFile.preCompileRegex(); // for efficiency

       // set up the JnetPcap stuff
       final StringBuilder errbuf=new StringBuilder();
       pcap=Pcap.openOffline(tracePath, errbuf);
       if(pcap==null){
          System.err.println(errbuf);
          return;
       }


       // loop through packets using handler implementation below
       // (The packet handler only checks the stateless policies)
       pcap.loop(Pcap.LOOP_INFINITE, new MyPacketHandler<StringBuilder>(), errbuf);

       pcap.close();

       //reopen pcap for stateful search
       pcap=Pcap.openOffline(tracePath, errbuf);

       // do the stateful search
       runStatefulIDS(mPolicyFile, pcap);

       pcap.close();


//       // print results for traces that are clean
//       for(Policy pol:mPolicyFile.policies){
//           if(!pol.matched){
//               System.out.println("No IDS Match ("+pol.name+")\n");
//           }
//       }
    }


    static void runStatefulIDS(PolicyFile policyFile, Pcap pcap){
        final Ip4 ip=new Ip4();

        //create JnetPcap flowmap (builtin convenience)
        JFlowMap superFlowMap = new JFlowMap();

        //fill map with all packets
        pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);

        // loop through policies (really only one per file in this lab)
        for(Policy policy:mPolicyFile.policies){
            //check if policy has already been matched
            if(policy.matched)
                continue;
            // skip non stateful policies
            if(!policy.isStateful)
                continue;

            SubPolicy sub = policy.subPolicies.get(0); // only one subpol in stateful policy


            for(JFlow flow:superFlowMap.values()){

                if(!flow.isReversable())
                    continue;

                List<JPacket> forward = flow.getForward();
                List<JPacket> reverse = flow.getReverse();

                //check forward flow
                if(forward.size()>0){

                    JPacket testPack=forward.get(0);
                    if(testPack.hasHeader(Ip4.ID)){
                        testPack.getHeader(ip);
                        if(ip.destinationToInt()==mPolicyFile.hostIP && !sub.isFromHost){
                            tryToMatchFlow(forward, testPack, policy, sub, ip);
                            continue;
                        }else if(ip.sourceToInt()==mPolicyFile.hostIP && sub.isFromHost){
                            tryToMatchFlow(forward, testPack, policy, sub, ip);
                            continue;
                        }
                    }
                }
                 //check reverse flow
                if(reverse.size()>0){

                    JPacket testPack=forward.get(0);
                    if(testPack.hasHeader(Ip4.ID)){
                        testPack.getHeader(ip);
                        if(ip.destinationToInt()==mPolicyFile.hostIP && !sub.isFromHost){
                            tryToMatchFlow(reverse, testPack, policy, sub, ip);
                            continue;
                        }else if(ip.sourceToInt()==mPolicyFile.hostIP && sub.isFromHost){
                            tryToMatchFlow(reverse, testPack, policy, sub, ip);
                            continue;
                        }
                    }
                }

            }
        }
    }

    // just a bit behind on time, we will finish up this function and turn in a bit late
    static boolean tryToMatchFlow(List<JPacket> packetList, JPacket first, Policy policy, SubPolicy sub, final Ip4 ip){

        StringBuilder fullFlowPayload = new StringBuilder();
        final Tcp tcp=new Tcp();
        final Udp udp=new Udp();

        boolean isTcp=false;
        if(first.hasHeader(tcp))
            isTcp=true;
        else if(!first.hasHeader(udp))
            return false;


        //again weed out flows that don't match the policy addresses, use the testpacket, first
        int sourceIP=ip.sourceToInt();
        int destIP=ip.destinationToInt();

        int sourcePort= isTcp? tcp.source() : udp.source();
        int destPort= isTcp? tcp.destination() : udp.destination();
        // check if packet is the right direction for rule, depending if host is sender or receiver
        if(mPolicyFile.hostIP==sourceIP){
            //check attacker IP
            if(!policy.attackerIP.any&&policy.attackerIP.ip!=destIP){
                return false;
            }

            //check source and destination Port
            if(!policy.host_port.any&&policy.host_port.port!=sourcePort){
                return false;
            }
            if(!policy.attacker_port.any&&policy.attacker_port.port!=destPort){
                return false;
            }
        }

        // other direction same thing
        if(mPolicyFile.hostIP==destIP){
            if(!policy.attackerIP.any&&policy.attackerIP.ip!=sourceIP){
                return false;
            }

            if(!policy.host_port.any&&policy.host_port.port!=destPort){
                return false;
            }
            if(!policy.attacker_port.any&&policy.attacker_port.port!=sourcePort){
                return false;
            }
        }


        // now the addresses all match the policy, just need to match the subpolicy (regex)

        // go through packetlist and compile the payloads into one string.
        if(isTcp){
            for(JPacket pack:packetList){
                pack.getHeader(tcp);
                fullFlowPayload.append(new String(tcp.getPayload(), StandardCharsets.UTF_8));
            }
        }
        else{
            for(JPacket pack:packetList){
                pack.getHeader(udp);
                fullFlowPayload.append(new String(udp.getPayload(), StandardCharsets.UTF_8));
            }
        }

        // try to match regex
        if(sub.compiledRegex.matcher(fullFlowPayload).find()){
            alert(first,ip,policy);
            //policy.matched=true;
        }

        return false;
    }

    static boolean matchIPPacket(int hostIP, Policy policy, SubPolicy subPolicy, JPacket packet, boolean isTcp, int sourceIP, int destIP, int sourcePort, int destPort, Tcp tcp, Udp udp){

        // first weed out packets that don't match

        // match tcp or udp
        if(policy.isTcp != isTcp){
            return false;
        }

        // check if packet is the right direction for rule, depending if host is sender or receiver
        if(mPolicyFile.hostIP==sourceIP){
            //check attacker IP
            if(!policy.attackerIP.any&&policy.attackerIP.ip!=destIP){
                return false;
            }

            //check source and destination Port
            if(!policy.host_port.any&&policy.host_port.port!=sourcePort){
                return false;
            }
            if(!policy.attacker_port.any&&policy.attacker_port.port!=destPort){
                return false;
            }
        }

        // other direction same thing
        if(mPolicyFile.hostIP==destIP){
            if(!policy.attackerIP.any&&policy.attackerIP.ip!=sourceIP){
                return false;
            }

            if(!policy.host_port.any&&policy.host_port.port!=destPort){
                return false;
            }
            if(!policy.attacker_port.any&&policy.attacker_port.port!=sourcePort){
                return false;
            }
        }
        //System.out.println("Ports and Addresses match");

        // now we have a packet that matches addresses, check if the current subpolicy is matched

        // first check direction


        String payload;
        if(isTcp){
            payload=new String(tcp.getPayload(), StandardCharsets.UTF_8);
        }else{
            payload=new String(udp.getPayload(), StandardCharsets.UTF_8);
        }



            if(subPolicy.isFromHost&&mPolicyFile.hostIP==destIP){
                return false;
            }

            // search for pattern in packet payload and return result
            return subPolicy.compiledRegex.matcher(payload).find();



    }


    // our implementation of the JPacketHandler interface, with nextPacket() method defined.
    static class MyPacketHandler<StringBuilder> implements JPacketHandler<StringBuilder>{

        final Ip4 ip=new Ip4();
        final Tcp tcp=new Tcp();
        final Udp udp=new Udp();

        int num=0;

        @Override
        public void nextPacket(JPacket packet, StringBuilder errbuf){

            boolean isTcp;

            // skip packets that are not tcp or udp protocol
            if(packet.hasHeader(ip)){
                if(packet.hasHeader(tcp))
                    isTcp=true;
                else if(packet.hasHeader(udp))
                    isTcp=false;
                else
                    return;
            }else
                return;

            int sourceIP=ip.sourceToInt();
            int destIP=ip.destinationToInt();

            int sourcePort= isTcp? tcp.source() : udp.source();
            int destPort= isTcp? tcp.destination() : udp.destination();


            // is possible to have multiple policies in a file, loop through them all
            // (none of the lab examples have more than 1)
            for(Policy policy : mPolicyFile.policies){
                if(policy.isStateful)//skip if stateful type policy
                    continue;
                if(policy.matched)// skip if this policy is already matched
                    continue;

                // test packet
                if(matchIPPacket(mPolicyFile.hostIP, policy, policy.subPolicies.get(policy.currentSubpolicy), packet, isTcp, sourceIP, destIP, sourcePort, destPort, tcp, udp)){

                    // if last subpolicy is matched, alert!!!
                    if(policy.currentSubpolicy == policy.subPolicies.size()-1){
                        //policy.matched=true;
                        alert(packet,ip,policy); /// print alert

                    // otherwise advance to next subpolicy
                    }else{
                        policy.currentSubpolicy++;
                    }
                }
            }
        }
    }

    static void alert(JPacket packet, Ip4 ip, Policy pol){
        System.out.println("Alert!!! IDS Policy ("+pol.name+") Matched");
        System.out.print("Dest IP: "+IP.intToIP(ip.destinationToInt()));
        System.out.println("  Source IP: "+IP.intToIP(ip.sourceToInt()));
    }
}





// Philip Wipf
// Evgenia Kolotiouk
// CSCI 476 Security Lab 5
// 19 April 2016

// PolicyFile encapsulation class


// PolicyFile reads in a text file and parses it according to the format
// described in lab5.  A bit of a mess but works well enough.

class PolicyFile{

    private static final String ipRegex="\\d*\\.\\d*\\.\\d*\\.\\d*";

    int hostIP;
    int i;
    Policy tempPolicy;
    List<Policy> policies=new ArrayList<>();

    public boolean readIn(String path){
        try{
            List<String> linelist=Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8);
            String[] lines=linelist.toArray(new String[linelist.size()]);

//            for(String s : lines){
//                System.out.println(s);
//            }

            i=0;
            String[] line1=lines[i].split("=");
            if(!line1[0].matches("\\s*host\\s*")){
                return false;
            }
            if(!line1[1].matches(ipRegex)){
                return false;
            }
            hostIP=IP.parseIP(line1[1]);

            i++;//skip blank line
            i++;
            if(i>=lines.length){
                return false;
            }

            while(i<lines.length){

                String[] line=lines[i].split("=");
                if(!line[0].equals("name")){
                    return false;
                }
                i++;
                if(!parsePolicy(lines, line[1])){
                    return false;
                }

            }
            return true;

        }catch(IOException|NumberFormatException e){
            e.printStackTrace();
            return false;
        }
    }

    boolean parsePolicy(String[] lines, String name){
        String[] line=lines[i].split("=");
        if(line.length!=2){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");
        if(!token.equals("type")){
            return false;
        }

        String type=line[1].replaceAll("\\s", "");
        i++;
        switch(type){
            case "stateful":
                return parseStatePolicy(lines, name, true);
            case "stateless":
                return parseStatePolicy(lines, name, false);
            default:
                return false;
        }
    }

    boolean parseStatePolicy(String[] lines, String name, boolean isStateful){
        tempPolicy=new Policy(name, isStateful);

        if(!isStateful){
            if(!parseProto(lines)){
                return false;
            }

            i++;
        }

        if(!parseHostPort(lines)){
            return false;
        }
        i++;

        if(!parseAttackerPort(lines)){
            return false;
        }
        i++;

        if(!parseAttacker(lines)){
            return false;
        }
        i++;

        if(!parseSubPolicy(lines)){
            return false;
        }
        i++;

        if(!isStateful){
            while(i<lines.length){
                String[] line=lines[i].split("=");
                if(line[0].equals("from_host")||line[0].equals("to_host")){
                    if(!parseSubPolicy(lines)){
                        return false;
                    }
                }else{
                    break;
                }
                i++;
            }

        }

        policies.add(tempPolicy);
        return true;
    }

    boolean parseHostPort(String[] lines){
        String[] line=lines[i].split("=");
        if(line.length!=2){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");

        if(token.equals("host_port")){
            String port=line[1].replaceAll("\\s", "");

            if(port.equals("any")){
                tempPolicy.host_port=new Port(0, true);
            }else{
                tempPolicy.host_port=new Port(Integer.parseInt(port), false);
            }
            return true;
        }
        return false;
    }

    boolean parseAttackerPort(String[] lines){
        String[] line=lines[i].split("=");
        if(line.length!=2){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");

        if(token.equals("attacker_port")){
            String port=line[1].replaceAll("\\s", "");

            if(port.equals("any")){
                tempPolicy.attacker_port=new Port(0, true);
            }else{
                tempPolicy.attacker_port=new Port(Integer.parseInt(port), false);
            }
            return true;
        }
        return false;
    }

    boolean parseAttacker(String[] lines){
        String[] line=lines[i].split("=");
        if(line.length!=2){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");

        if(token.equals("attacker")){
            String ip=line[1].replaceAll("\\s", "");

            if(ip.equals("any")){
                tempPolicy.attackerIP=new IP(0, true);
            }else{
                tempPolicy.attackerIP=new IP(IP.parseIP(ip), false);
            }
            return true;
        }
        return false;
    }

    boolean parseProto(String[] lines){
        String[] line=lines[i].split("=");
        if(line.length!=2){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");

        if(token.equals("proto")){
            String proto=line[1].replaceAll("\\s", "");
            if(proto.equals("tcp")){
                tempPolicy.isTcp=true;
                return true;
            }else if(proto.equals("udp")){
                tempPolicy.isTcp=false;
                return true;
            }
        }
        return false;
    }

    boolean parseSubPolicy(String[] lines){
        String[] line=lines[i].split("=");
        if(line.length!=2&&line.length!=3){
            return false;
        }
        String token=line[0].replaceAll("\\s", "");

        String regex=line[1].replaceAll("\"","");

        switch(token){
            case "from_host":
                if(line.length==2){
                    tempPolicy.subPolicies.add(new SubPolicy(true, regex));
                }else{
                    String[] temp=line[1].split(" ");
                    if(temp.length!=3){
                        return false;
                    }
                    if(!temp[1].equals("with")||!temp[2].equals("flags")){
                        return false;
                    }
                    tempPolicy.subPolicies.add(new SubPolicy(true, temp[0], line[2]));
                }
                return true;
            case "to_host":
                if(line.length==2){
                    tempPolicy.subPolicies.add(new SubPolicy(false, regex));
                }else{
                    String[] temp=line[1].split(" ");
                    if(temp.length!=3){
                        return false;
                    }
                    if(!temp[1].equals("with")||!temp[2].equals("flags")){
                        return false;
                    }
                    tempPolicy.subPolicies.add(new SubPolicy(false, temp[0], line[2]));
                }
                return true;
            default:
                return false;
        }
    }

    public String toString(){
        StringBuilder sb=new StringBuilder();

        sb.append("HostIP: "+IP.intToIP( hostIP)+"\n");
        for(Policy pol : policies){
            sb.append(pol.name+"\n");
            if(!pol.isStateful){
                sb.append("Stateless\n");
                sb.append("proto: "+(pol.isTcp?"TCP":"UDP")+"\n");
            }else{
                sb.append("Stateful\n");
            }
            sb.append("host_port: "+pol.host_port+"\n");
            sb.append("attk_port: "+pol.attacker_port+"\n");
            sb.append("attk IP:  "+pol.attackerIP+"\n");
            for(SubPolicy sub : pol.subPolicies){
                sb.append((sub.isFromHost?"from_host: ":"to_host: ")+sub.regex+"\n");
            }

        }
        return sb.toString();
    }

    public void preCompileRegex(){
        for(Policy pol:policies){
            for(SubPolicy sub: pol.subPolicies){
                sub.compiledRegex = Pattern.compile(sub.regex);
            }
        }
    }

}

class Policy{
    boolean isStateful;
    boolean isTcp;
    String name;
    Port host_port;
    Port attacker_port;
    IP attackerIP;
    List<SubPolicy> subPolicies=new ArrayList<>();

    int currentSubpolicy=0;
    boolean matched=false;

    Policy(String name, boolean isStateful){
        this.name=name;
        this.isStateful=isStateful;
    }
}

class SubPolicy{

    boolean isFromHost;
    String regex;
    String flags;
    Pattern compiledRegex;

    SubPolicy(boolean isFrom, String regex){
        this.isFromHost=isFrom;
        this.regex=regex;
    }

    SubPolicy(boolean isFrom, String regex, String flags){
        this.isFromHost=isFrom;
        this.regex=regex;
        this.flags=flags;
    }
}

class Port{

    boolean any;
    int port;

    Port(int port, boolean any){
        this.port=port;
        this.any=any;
    }

    public String toString(){
        return any?"any":(port+"");
    }
}

class IP{

    boolean any;
    int ip;

    IP(int ip, boolean any){
        this.ip=ip;
        this.any=any;
    }

    static int parseIP(String s){
        int[] ip=new int[4];
        String[] parts=s.split("\\.");

        for(int i=0;i<4;i++){
            ip[i]=Integer.parseInt(parts[i]);
        }

        long ipNumbers=0;
        for(int i=0;i<4;i++){
            ipNumbers+=ip[i]<<(24-(8*i));
        }
        return (int)ipNumbers;
    }

    static String intToIP(int ip){
        StringBuilder s=new StringBuilder();
        int[] temp=new int[4];
        for(int i=0; i<4; i++){
            temp[i]=(int)(ip&0xFF);
            ip=ip>>8;
        }
        for(int i=3; i>=0; i--){
            s.append(temp[i]);
            if(i>0){
                s.append(".");
            }
        }

        return s.toString();
    }

    public String toString(){
        return any ? "any" : (ip+intToIP(ip));
    }


}
