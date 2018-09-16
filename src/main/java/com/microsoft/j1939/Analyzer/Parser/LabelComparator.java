package com.microsoft.j1939.Analyzer.Parser;

import java.util.Comparator;

import com.microsoft.j1939.Analyzer.Schema.Label;

/**
 *
 * @author Neil Brittliff
 */
class LabelComparator implements Comparator<Label> {

    @Override
    public int compare( Label l1, Label l2){
        return l1.getValue().compareTo(l2.getValue());        
    }
    
}