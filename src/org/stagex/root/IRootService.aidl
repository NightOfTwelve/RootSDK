package org.stagex.root;

interface IRootService {
    int version();
    int exec(in String[] cmd, in String[] env, in String cwd);
}