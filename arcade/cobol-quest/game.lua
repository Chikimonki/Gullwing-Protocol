-- COBOL Quest: Find the bug before the bank crashes
-- Uses the Gullwing-Swan parser to generate puzzles

local COBOLQuest = {
    levels = {
        {
            name = "The Missing Period",
            cobol = [[
       IDENTIFICATION DIVISION.
       PROGRAM-ID. BANKING-APP.
       PROCEDURE DIVISION.
           COMPUTE BALANCE = BALANCE - WITHDRAWAL
           DISPLAY "TRANSACTION COMPLETE"
            ]],
            bug = "Missing period after WITHDRAWAL",
            hint = "COBOL statements end with a period. Look carefully.",
        },
        {
            name = "The GOTO Trap",
            cobol = [[
       IDENTIFICATION DIVISION.
       PROGRAM-ID. PAYROLL.
       PROCEDURE DIVISION.
           IF SALARY > 10000 THEN
               GOTO BONUS
           ELSE
               DISPLAY "STANDARD PAY"
           END-IF.
           BONUS.
           DISPLAY "MASSIVE BONUS"
            ]],
            bug = "Logic error: BONUS executes for ALL employees due to GOTO",
            hint = "The GOTO bypasses the IF-ELSE logic.",
        },
    },
}

-- Display function
print("🦆 COBOL QUEST — Find the Bug Before the Bank Crashes")
print("")
print("Levels:")
for i, level in ipairs(COBOLQuest.levels) do
    print(string.format("  %d. %s", i, level.name))
    print(string.format("     Bug: %s", level.bug))
    print(string.format("     Hint: %s", level.hint))
    print("")
    print("COBOL Code:")
    print(level.cobol)
    print("")
end

print("How to play: Examine the COBOL code and identify the bug.")
print("This teaches banking software security - critical for COBOL systems still in use.")
