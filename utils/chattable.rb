class ChatTable
    def initialize()
    end

    def genTable(arr)
        output = ""
        values = {}

        arr.each do |element|
            vals = {}
            element.each do |key, value|
                vals[key] = value.to_s.length
            end

            vals.each do |key, val|
                if values[key] != nil
                    if val > values[key]
                        values[key] = val
                    end
                else
                    values[key] = val
                end
            end
        end
        
        table = ""
        header = ""
        total_length = 0
        values.each do |column, length|
            total_length += length+3
            header += returnPadded(column.upcase, length+3, min=column.length+3)
        end

        header += "\n"

        (0..total_length).each do |iter|
            header += "-"
        end

        arr.each do |element|
            element.each do |key, val|
                length = values[key]
                table += returnPadded(val.to_s, length+3)
            end
            table += "\n"
        end

        output += "#{header}\n"
        output += "#{table}\n"
    end

    def returnPadded(str, length, min=length)
        return (str.length > length) ? str.slice(0..min) : str.ljust(length, ' ')
    end
end

