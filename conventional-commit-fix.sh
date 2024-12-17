#!/bin/bash
# filepath: conventional-commit-fix.sh

set -e  # Exit on error

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}⚠️  Conventional Commit Message Fixer ⚠️${NC}"
echo -e "${RED}WARNING: This script rewrites git history. Only use on branches that haven't been shared.${NC}"
echo -e "If you've already pushed this branch, you'll need to force push after using this script.\n"

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: You have uncommitted changes. Please commit or stash them first.${NC}"
    exit 1
fi

# Save current branch
current_branch=$(git rev-parse --abbrev-ref HEAD)

# Number of commits to process
read -p "How many commits do you want to process? " num_commits

# Verify the input is a number
if ! [[ "$num_commits" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: Please enter a valid number.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}Choose fixing strategy:${NC}"
echo "1) Interactive rebase (manual edit of each commit)"
echo "2) Auto-fix commits with common patterns"
read -p "Select option (1/2): " strategy

# Backup branch
backup_branch="${current_branch}_backup_$(date +%s)"
echo -e "\n${GREEN}Creating backup branch: $backup_branch${NC}"
git branch $backup_branch

if [ "$strategy" == "1" ]; then
    echo -e "\n${GREEN}Starting interactive rebase for $num_commits commits...${NC}"
    echo -e "${YELLOW}Change 'pick' to 'reword' for commits you want to modify.${NC}"
    echo -e "Commit format should be: ${GREEN}type(scope): message${NC}"
    echo -e "Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert\n"
    
    # Start interactive rebase
    git rebase -i HEAD~$num_commits
    
elif [ "$strategy" == "2" ]; then
    echo -e "\n${GREEN}Auto-fixing $num_commits commits with common patterns...${NC}"
    
    # Create temporary script for message conversion
    cat > /tmp/convert_message.rb << 'EOF'
message = STDIN.read

# Common patterns to fix
patterns = {
  /^Update/i => 'fix: Update',
  /^Updated/i => 'fix: Updated',
  /^Fix/i => 'fix: Fix',
  /^Fixed/i => 'fix: Fixed', 
  /^Bug fix/i => 'fix: ',
  /^Add/i => 'feat: Add',
  /^Added/i => 'feat: Added',
  /^Implement/i => 'feat: Implement',
  /^Implemented/i => 'feat: Implemented',
  /^Remove/i => 'refactor: Remove',
  /^Removed/i => 'refactor: Removed',
  /^Refactor/i => 'refactor: ',
  /^Improve/i => 'perf: Improve',
  /^Improved/i => 'perf: Improved',
  /^Document/i => 'docs: ',
  /^Documentation/i => 'docs: ',
  /^Test/i => 'test: ',
  /^Testing/i => 'test: ',
  /^CI:/i => 'ci: ',
  /^Build:/i => 'build: '
}

# Skip if already conventional
if message =~ /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9\-]+\))?!?: /i
  print message
  exit 0
end

# Try to match patterns
matched = false
patterns.each do |pattern, replacement|
  if message =~ pattern
    message = message.sub(pattern, replacement)
    matched = true
    break
  end
end

# If no pattern matched, add a generic prefix
unless matched
  message = "chore: " + message
end

print message
EOF

    # Run filter-branch
    git filter-branch -f --msg-filter 'ruby /tmp/convert_message.rb' HEAD~$num_commits..HEAD
    
    # Clean up
    rm /tmp/convert_message.rb

else
    echo -e "${RED}Invalid option selected.${NC}"
    exit 1
fi

echo -e "\n${GREEN}✅ Complete!${NC}"
echo -e "Original history saved in branch: ${YELLOW}$backup_branch${NC}"
echo -e "If you've already pushed this branch, you'll need to: ${YELLOW}git push --force${NC}"
echo -e "To verify changes: ${YELLOW}git log${NC}"