// This class reads in a configuration file, called "config.txt", and makes
// its contents easily available to Java code.
//
// A configuration entry can be read as a String, like this:
//
//         String str = Config.getAsString("entryname");
//
// An entry can be read as an integer, like this:
//
//         int i = Config.getAsInt("entryname");
//

import java.io.FileInputStream;
import java.util.Properties;

import java.io.IOException;


public class Config {

  private static boolean needInit = true;

  private static Properties props;

  private static void init(String configFileName) {
    needInit = false;
    try{
      FileInputStream fis = new FileInputStream(configFileName);
      if(fis != null){
	props = new Properties();
	props.load(fis);
      }
    }catch(IOException x){
      x.printStackTrace(System.err);
    }
  }
  
  public static String getAsString(String configFileName, String name) {
    if(needInit)    init(configFileName);
    return props.getProperty(name);
  }

  public static int getAsInt(String configFileName, String name) {
    if(needInit)    init(configFileName);
    return Integer.parseInt(getAsString(configFileName, name));
  }
}
