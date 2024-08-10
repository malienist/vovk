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
            String filePath = "C:\\Users\\malie\\Documents\\ghidra_generated_rule.yar";
            fileWriter = new FileWriter(filePath);

            // Extract strings from raw memory
            List<String> strings = extractStringsFromMemory();

            if (strings.isEmpty()) {
                fileWriter.write("No strings found in the current program.");
            } else {
                // Select 20 random strings from the list
                List<String> randomStrings = getRandomStrings(strings, 20);

                // Convert selected strings to hex format
                List<String> hexStrings = convertStringsToHex(randomStrings);

                String yaraRule = generateYaraRule(hexStrings, "ghidra_generated_rule");
                fileWriter.write(yaraRule);
            }

            fileWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fileWriter != null) {
                fileWriter.close();
            }
        }
    }

    private List<String> extractStringsFromMemory() {
        List<String> strings = new ArrayList<>();
        int minLength = 4;  // Minimum length of string to consider

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            byte[] data = new byte[(int) block.getSize()];
            try {
                block.getBytes(block.getStart(), data);
            } catch (MemoryAccessException e) {
                println("Error reading memory block at " + block.getStart() + ": " + e.getMessage());
                continue;  // Skip this block and move to the next one
            }

            StringBuilder currentString = new StringBuilder();
            for (byte b : data) {
                if (b >= 32 && b <= 126) { // Printable ASCII range
                    currentString.append((char) b);
                } else {
                    if (currentString.length() >= minLength) {
                        strings.add(currentString.toString());
                    }
                    currentString.setLength(0);
                }
            }

            if (currentString.length() >= minLength) {
                strings.add(currentString.toString());
            }
        }

        return strings;
    }

    private List<String> getRandomStrings(List<String> strings, int count) {
        // Shuffle the list to randomize
        Collections.shuffle(strings);

        // Select up to 'count' strings, or fewer if the list is smaller
        int limit = Math.min(count, strings.size());
        List<String> selectedStrings = new ArrayList<>(strings.subList(0, limit));

        // Sort the selected strings for better distribution
        Collections.sort(selectedStrings);

        return selectedStrings;
    }

    private List<String> convertStringsToHex(List<String> strings) {
        List<String> hexStrings = new ArrayList<>();
        for (String str : strings) {
            StringBuilder hex = new StringBuilder();
            for (char c : str.toCharArray()) {
                hex.append(String.format("%02x ", (int) c));
            }
            hexStrings.add(hex.toString().trim());
        }
        return hexStrings;
    }

    private String generateYaraRule(List<String> stringsList, String ruleName) {
        StringBuilder yaraRule = new StringBuilder();
        yaraRule.append("rule ").append(ruleName).append(" {\n");
        yaraRule.append("    strings:\n");

        int idx = 0;
        for (String hexString : stringsList) {
            yaraRule.append("        $str").append(idx).append(" = { ").append(hexString).append(" }\n");
            idx++;
        }

        yaraRule.append("    condition:\n");
        yaraRule.append("        all of them\n");
        yaraRule.append("}\n");

        return yaraRule.toString();
    }
}
