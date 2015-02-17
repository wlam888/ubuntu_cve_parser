import java.io.*;
import java.util.*;
import java.util.regex.*;

public class ubuntuParser 
{
   
//**************************main()*****************************  
    public static void main(String[] args) 
    {

       File directory = new File("ubuntu-cve-tracker/active");
       File[] fList = directory.listFiles();
       for (File file : fList)
       {
          String fName = file.getName();
      
          if(fName.contains("CVE-201"))
          {
             String workingDir = System.getProperty("user.dir");
             String absPath = workingDir +"/ubuntu-cve-tracker/active" +File.separator +file.getName();
             
             parseAdv(absPath);
          }
       }
       cleanUp();

    }
//***************************parseAdv()*************************    
    public static void parseAdv(String fName) 
    {  

       List<String> lines = new ArrayList<String>();
       String token1 = "";
       Pattern delimiters = Pattern.compile("\\n[\\n]+"); 
       
        try
        {
           Scanner inFile1 = new Scanner(new File(fName)).useDelimiter(delimiters);
           while (inFile1.hasNext()) 
           {
              token1 = inFile1.next();
              lines.add(token1);
           }
           inFile1.close();
        
          String[] linesArray = lines.toArray(new String[0]);
    
          int blocks = linesArray.length; 

          FileWriter writer = new FileWriter("parseOutput.csv",true);

          String set1 = linesArray[0].toString();
          String[] set1arr = set1.split(":\t|\n");
          String CVENum;
          if(set1arr[0].contains("Candidate"))
          {
             CVENum = set1arr[0];
          }
          else
          {
             CVENum = set1arr[1];
          }

          String set2 = linesArray[1].toString(); 
          String[] set2arr = set2.split(":\t|\n");
          String PackageName = set2arr[0];
          
           for (int i=2; i<set2arr.length; i++)  
           {  
              writer.append(CVENum.replaceAll(":", ",")+", "
              +PackageName.replaceAll(":", ",")
              +" "+set2arr[i].replaceAll(":", ",")
              +"\n");   
           }
           
          if(blocks>=3)
          {
             String set3 = linesArray[2].toString(); 
             String[] set3arr = set3.split(":\t|\n");
             String Package2Name = set3arr[0];

             for (int i=2; i<set3arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package2Name.replaceAll(":", ",")
                 +" "+set3arr[i].replaceAll(":", ",")
                 +"\n");   
             }
       
          }
          
          if(blocks>=4)
          {
             String set4 = linesArray[3].toString(); 
             String[] set4arr = set4.split(":\t|\n");
             String Package3Name = set4arr[0];

             for (int i=2; i<set4arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package3Name.replaceAll(":", ",")
                 +" "+set4arr[i].replaceAll(":", ",")
                 +"\n");   
             }
          }
          
          if(blocks>=5)
          {
             String set5 = linesArray[4].toString(); 
             String[] set5arr = set5.split(":\t|\n");
             String Package4Name = set5arr[0];

             for (int i=2; i<set5arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package4Name.replaceAll(":", ",")
                 +" "+set5arr[i].replaceAll(":", ",")
                 +"\n");   
             }
          }
          
          if(blocks>=6)
          {  
             String set6 = linesArray[5].toString(); 
             String[] set6arr = set6.split(":\t|\n");
             String Package5Name = set6arr[0];

             for (int i=2; i<set6arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package5Name.replaceAll(":", ",")
                 +" "+set6arr[i].replaceAll(":", ",")
                 +"\n");   
             }
          }
          
          if(blocks>=7)
          { 
             String set7 = linesArray[6].toString(); 
             String[] set7arr = set7.split(":\t|\n");
             String Package6Name = set7arr[0];

             for (int i=2; i<set7arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package6Name.replaceAll(":", ",")
                 +" "+set7arr[i].replaceAll(":", ",")
                 +"\n");   
             }
          }
          
          if(blocks>=8)
          { 
             String set8 = linesArray[7].toString(); 
             String[] set8arr = set8.split(":\t|\n");
             String Package7Name = set8arr[0];

             for (int i=2; i<set8arr.length; i++)  
             {  
                 writer.append(CVENum.replaceAll(":", ",")+", "
                 +Package7Name.replaceAll(":", ",")
                 +" "+set8arr[i].replaceAll(":", ",")
                 +"\n");   
             }
          }

	      writer.flush();
	      writer.close();
	 
        }catch(Exception e){
            e.printStackTrace();
      }
    }
//*****************************cleanUp()***********************    
   public static void cleanUp()  
    {
                            
        try
        {
		   Scanner sc = new Scanner(new File("parseOutput.csv"));
		   FileWriter writer = new FileWriter("ubuntu_cve.csv");
		   String line = "";
		   String cvsSplitBy = ",";
		   
		   String[] column = new String[5]; 
		   
		   writer.append("Vendor,Release,CVE,Package,Status"+"\n");
		   
		   while (sc.hasNext()) 
		   {   
		       line = sc.nextLine();
		       
               if(!line.contains("Patches_"))
               {
                  continue;
               }
               else
               {
                  column = line.split(cvsSplitBy);   
               }
		       	       		       
		       int entryNums = column.length;
		       
		       if((entryNums<5) ||column[3].contains("upstream") || column[3].contains("devel") 
		       || column[3].contains("  break-fix") || column[3].contains("Tags") || column[3].contains("other") 
		       || column[3].contains("unknown") || column[3].contains("unknown") || column[3].contains("vendor") )
		       {
		          continue;
		        }
		        else
		        {	     
		   	      writer.append(column[0].replaceAll("Candidate","Ubuntu")+","
		   	      +column[3].split("_")[0].replaceAll("dapper_*","6.06").replaceAll("hardy*","8.04").replaceAll("intrepid_*","8.10")
		   	      .replaceAll("jaunty_*","9.04").replaceAll("karmic_*","9.10")
		   	      .replaceAll("lucid_*","10.04").replaceAll("maverick_*","10.10").replaceAll("natty_*","11.04")
		   	      .replaceAll("oneiric_*","11.11").replaceAll("precise_*","12.04").replaceAll("quantal_*","12.10")
		   	      .replaceAll("raring_*","13.04").replaceAll("saucy_*","13.10").replaceAll("trusty_*","14.04")
		   	      .replaceAll("utopic_*","14.10").replaceAll("needs-triage", "")+","+column[1]+","+column[2].replaceAll("Patches_","")+","
		   	      +column[4]+"\n");
		   	   }
            

		   }
		   sc.close();
		   writer.close();
		   
		   boolean success = (new File("parseOutput.csv")).delete();
		   
		   }catch(Exception e){
            e.printStackTrace();
            }
	}
}