from pyspark.sql import SparkSession
from pyspark.sql.functions import col

def spark_filter_packets(packet_list, protocol=None):
    spark = SparkSession.builder.appName("PacketFilter").getOrCreate()
    
    # Convert packet list to Spark DataFrame
    df = spark.createDataFrame(packet_list)

    # Optional: Filter by protocol
    if protocol:
        df = df.filter(col("proto") == protocol)

    # Filter out malformed or suspicious packets
    df = df.filter((col("len") > 0) & (col("src").isNotNull()) & (col("dst").isNotNull()))

    # Convert back to Python list of dicts
    return df.toPandas().to_dict(orient="records")
