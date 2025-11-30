package utils;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.UUID;

public class FileGenerator {

    private static long size = 128;

    public static File generateFile(String client){

        File dir = new File(client);
        if(dir.mkdir()){
            System.out.println("Directory " + client + " has been created successfully");
        }

        File file = new File(String.format("%s/%s-%s.txt", client, client, UUID.randomUUID().toString()));
        RandomAccessFile rafile;
        try {
            rafile = new RandomAccessFile(file, "rw");
            rafile.setLength(size);
            System.out.println("CREATED FILEEEEEEEEEEEEEEEEEEEE " + file.getAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
        }
        return file;
    }
}
