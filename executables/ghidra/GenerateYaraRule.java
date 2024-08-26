import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class GenerateYaraRule extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FileWriter fileWriter = null;
        try {
            // Define the path where you want your YARA ruleset to be saved
            String filePath = "C:\\your\\path\\to\\ghidra_generated_rule.yar";
            fileWriter = new FileWriter(filePath);

            // Extract all strings from the application's memory
            List<String> strings = extractStringsFromMemory();

            // We need to check if any strings were found
            if (strings.isEmpty()) {
                // If no strings were found, write a message to the file
                fileWriter.write("Could not create YARA rules as no strings found in the current application.");
            } else {
                // If strings were found, select 20 random strings from the list | You can change this number to anything you want according to your needs!
                List<String> randomStrings = getRandomStrings(strings, 20);

                // Convert the selected strings to their hexadecimal representation
                List<String> hexStrings = convertStringsToHex(randomStrings);

                // Generate a YARA rule from the hex strings
                String yaraRule = generateYaraRule(hexStrings, "ghidra_generated_rule");
                
                // Write the generated YARA rule to the filepath as defined earlier
                fileWriter.write(yaraRule);
            }

            // Ensure all data is written to the file
            fileWriter.flush();
        } catch (IOException e) {
            // Print any IO exceptions to the console
            e.printStackTrace();
        } finally {
            // Close the file writer to free system resources
            if (fileWriter != null) {
                fileWriter.close();
            }
        }
    }

    // Method to extract printable strings from the application's memory
    private List<String> extractStringsFromMemory() {
        List<String> strings = new ArrayList<>();
        int minLength = 4;  // Minimum length of a string to be considered

        // Iterate over all memory blocks in the program
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            byte[] data = new byte[(int) block.getSize()];  // Allocate a byte array for the block data
            try {
                // Read the bytes from the memory block
                block.getBytes(block.getStart(), data);
            } catch (MemoryAccessException e) {
                // If there's an error accessing memory, print a message and skip this block
                println("Error reading memory block at " + block.getStart() + ": " + e.getMessage());
                continue;
            }

            StringBuilder currentString = new StringBuilder();
            // Iterate over the bytes in the memory block
            for (byte b : data) {
                if (b >= 32 && b <= 126) { // Check if the byte is a printable ASCII character
                    currentString.append((char) b);
                } else {
                    // If a non-printable character is found, check if the current string is long enough
                    if (currentString.length() >= minLength) {
                        strings.add(currentString.toString());  // Add the string to the list
                    }
                    currentString.setLength(0);  // Reset the string builder for the next string
                }
            }

            // Add any remaining string after the loop ends
            if (currentString.length() >= minLength) {
                strings.add(currentString.toString());
            }
        }

        return strings;  // Return the list of extracted strings
    }

    // Method to randomly select a specified number of strings from a list
    private List<String> getRandomStrings(List<String> strings, int count) {
        // Shuffle the list to randomize the order of strings
        Collections.shuffle(strings);

        // Select up to 'count' strings from the shuffled list
        int limit = Math.min(count, strings.size());
        List<String> selectedStrings = new ArrayList<>(strings.subList(0, limit));

        // Sort the selected strings for better distribution in the YARA rule
        Collections.sort(selectedStrings);

        return selectedStrings;  // Return the list of selected strings
    }

    // Method to convert a list of strings to their hexadecimal representation
    private List<String> convertStringsToHex(List<String> strings) {
        List<String> hexStrings = new ArrayList<>();
        for (String str : strings) {
            StringBuilder hex = new StringBuilder();
            for (char c : str.toCharArray()) {
                hex.append(String.format("%02x ", (int) c));  // Convert each character to hex and add it to the string
            }
            hexStrings.add(hex.toString().trim());  // Add the hex string to the list
        }
        return hexStrings;  // Return the list of hex strings
    }

    // Method to generate a YARA rule from a list of hex strings
    private String generateYaraRule(List<String> stringsList, String ruleName) {
        StringBuilder yaraRule = new StringBuilder();
        yaraRule.append("rule ").append(ruleName).append(" {\n");
        yaraRule.append("    strings:\n");

        int idx = 0;
        // Add each hex string as a YARA string variable
        for (String hexString : stringsList) {
            yaraRule.append("        $str").append(idx).append(" = { ").append(hexString).append(" }\n");
            idx++;
        }

        // Add the condition to the YARA rule (in this case, all strings must be present)
        yaraRule.append("    condition:\n");
        yaraRule.append("        all of them\n");
        yaraRule.append("}\n");

        return yaraRule.toString();  // Return the generated YARA rule as a string
    }
}
