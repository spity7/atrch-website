import PropTypes from "prop-types";

const AwardItem = ({ data }) => {
    return (
        <div className="item">
            <p>{data.cate}</p>
            <h4
                dangerouslySetInnerHTML={{
                    __html: data.title,
                }}
            />
        </div>
    );
};

AwardItem.propTypes = {
    data: PropTypes.object,
};

export default AwardItem;
